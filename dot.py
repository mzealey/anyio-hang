#!/usr/bin/env python3
import argparse
import logging
import ssl

import anyio
from anyio.streams.tls import TLSListener
from anyio.streams.buffered import BufferedByteReceiveStream
from anyio.abc.sockets import SocketAttribute

import dns.message
import dns.rdtypes.ANY.CNAME

async def handle_dns_query(query, logger):
    dnsq = dns.message.from_wire(query)
    qname = dnsq.question[0].name 
    dnsr = dns.message.make_response(dnsq)
    answer_rrset = dnsr.section_from_number(1)      # get the answer
    rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.CNAME)
    rrset.add(dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, dns.name.from_text('foo.bar.')))
    answer_rrset.append(rrset)
    dnsr.set_rcode(dns.rcode.NOERROR)

    logger.debug("sending response: " + str(dnsr))
    return dnsr.to_wire()

class HandleClient(object):
    def __init__(self, args, logger):
        self.args = args
        self.logger = logger

    async def handle(self, client):
        try:
            self.logger.debug("Received client connection")
            async with client:
                await self._handle(client)
        except anyio.BrokenResourceError:
            # connection exited without proper termination.
            pass
        except Exception as e:
            self.logger.exception(e)

        self.logger.debug("Client exit")

    async def _handle(self, client):
        buffered_client = BufferedByteReceiveStream(client)

        # Support multiple queries
        while True:
            self.logger.debug("Reading message from client")

            # TODO: Issue with infinite loops here with kdig? https://github.com/agronholm/anyio/issues/162
            # First 2 bytes of protocol are how much to read
            len_to_read = int.from_bytes(await buffered_client.receive_exactly(2), "big")
            query = await buffered_client.receive_exactly(len_to_read)

            response = await handle_dns_query(query, self.logger)

            len_to_write = len(response).to_bytes(2, byteorder="big")
            await client.send(len_to_write + response)

def configure_logger(name='', level='DEBUG'):
    """
    :param name: (optional) name of the logger, default: ''.
    :param level: (optional) level of logging, default: DEBUG.
    :return: a logger instance.
    """
    logging.basicConfig(format='%(asctime)s: %(levelname)8s: %(message)s')
    logger = logging.getLogger(name)
    level_name = level.upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise Exception("Invalid log level name : %s" % level_name)
    logger.setLevel(level)
    return logger

def proxy_parser_base(port=853, secure=True):
    # These stolen from doh-proxy/dohproxy/utils.py to keep interface the same
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--listen-address',
        default=['::1'],
        nargs='+',
        help='A list of addresses the proxy should listen on. '
             'Default: [%(default)s]'
    )
    parser.add_argument(
        '--certfile',
        help='SSL cert file.',
        required=secure
    )
    parser.add_argument(
        '--keyfile',
        help='SSL key file.',
        required=secure
    )
    parser.add_argument(
        '--upstream-resolver',
        default='::1',
        help='Upstream recursive resolver to send the query to. '
             'Default: [%(default)s]',
    )
    parser.add_argument(
        '--listen-port',
        default=port,
        type=int,
        help='Port to listen on. Default: [%(default)s]',
    )
    parser.add_argument(
        '--level',
        default='DEBUG',
        help='log level [%(default)s]',
    )

    return parser

async def main():
    parser = proxy_parser_base()
    args = parser.parse_args()
    logger = configure_logger('dot-proxy', args.level)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.check_hostname = False
    #context.tls_standard_compatible = False     # Don't worry about EOFs

    # Load the server certificate and private key
    context.load_cert_chain(args.certfile, keyfile=args.keyfile)
    #context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    #                | ssl.OP_NO_COMPRESSION)
    #context.set_ciphers('ECDHE+AESGCM')

    listener = TLSListener(await anyio.create_tcp_listener(local_port=args.listen_port), context, standard_compatible=False)
    handler = HandleClient(args, logger).handle
    while True:
        try:
            await listener.serve(handler)
        except anyio.BrokenResourceError:       # happens when something connects & disconnects with no traffic
            pass
        except ssl.SSLError as e:
            if 'SSLV3_ALERT_BAD_CERTIFICATE' not in str(e):     # caused when connecting with incorrect hostname
                logger.exception(e)
        except Exception as e:
            # Just log and keep on going rather than taking the service down...
            logger.exception(e)

if __name__ == '__main__':
    anyio.run(main)
