`rfc9001-client.bin` is the protected Client Initial test vector from RFC 9001,
Appendix A.2: https://www.rfc-editor.org/rfc/rfc9001#appendix-A.2
It must decrypt to the SNI `example.com` independently of generated test packets.

The other fixtures are synthetic, authenticated QUIC v1/v2 Client Initials with
minimal TLS ClientHellos, the same public test DCID, and packet numbers 0/1.
`fragment-0/1.bin` split one ClientHello across two CRYPTO frames/datagrams.
They contain no captured user traffic or application data.
