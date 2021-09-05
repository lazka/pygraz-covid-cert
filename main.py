"""
references:

* https://harrisonsand.com/posts/covid-certificates/
* https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview
* docs of all used libraries
"""


async def fetch_austria_data_and_verify(thing: str):
    # See https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview
    # for details. This is Austria specific, but uses the same technologies as the rest

    # First we fetch the signature
    # (which is a COSE message where the payload is the checksum of the real content)
    import httpx
    from cose.messages import CoseMessage
    async with httpx.AsyncClient() as client:
        r = await client.get(f"https://dgc-trust.qr.gv.at/{thing}sig")
        r.raise_for_status()
        signature = r.content
    cose_msg = CoseMessage.decode(signature)

    # Use the official certificate to create a COSE key
    from cryptography import x509
    from cose.keys import EC2Key
    AUSTRIA_API_CERT = b"""\
-----BEGIN CERTIFICATE-----
MIIB1DCCAXmgAwIBAgIKAXnM+Z3eG2QgVzAKBggqhkjOPQQDAjBEMQswCQYDVQQG
EwJBVDEPMA0GA1UECgwGQk1TR1BLMQwwCgYDVQQFEwMwMDExFjAUBgNVBAMMDUFU
IERHQyBDU0NBIDEwHhcNMjEwNjAyMTM0NjIxWhcNMjIwNzAyMTM0NjIxWjBFMQsw
CQYDVQQGEwJBVDEPMA0GA1UECgwGQk1TR1BLMQ8wDQYDVQQFEwYwMDEwMDExFDAS
BgNVBAMMC0FUIERHQyBUTCAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEl2tm
d16CBHXwcBN0r1Uy+CmNW/b2V0BNP85y5N3JZeo/8l9ey/jIe5mol9fFcGTk9bCk
8zphVo0SreHa5aWrQKNSMFAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRTwp6d
cDGcPUB6IwdDja/a3ncM0TAfBgNVHSMEGDAWgBQfIqwcZRYptMGYs2Nvv90Jnbt7
ezAKBggqhkjOPQQDAgNJADBGAiEAlR0x3CRuQV/zwHTd2R9WNqZMabXv5XqwHt72
qtgnjRgCIQCZHIHbCvlgg5uL8ZJQzAxLavqF2w6uUxYVrvYDj2Cqjw==
-----END CERTIFICATE-----"""
    cert = x509.load_pem_x509_certificate(AUSTRIA_API_CERT)
    public_key = cert.public_key()
    x = public_key.public_numbers().x.to_bytes(32, "big")
    y = public_key.public_numbers().y.to_bytes(32, "big")
    cose_key = EC2Key(crv='P_256', x=x, y=y, optional_params={'ALG': 'ES256'})

    # set the key and verify the signature
    cose_msg.key = cose_key
    cose_msg.verify_signature()

    # Now load the content and check that the checksum matches
    import cbor2
    import hashlib
    async with httpx.AsyncClient() as client:
        r = await client.get(f"https://dgc-trust.qr.gv.at/{thing}")
        r.raise_for_status()
        content = r.content
    if cbor2.loads(cose_msg.payload)[2] != hashlib.sha256(content).digest():
        raise Exception()

    # Now we can trust the content, so decode it
    return cbor2.loads(content)


async def main(filename: str):
    # We convert the input PDF to a PIL image
    from pdf2image import convert_from_path
    image = convert_from_path(filename)[0]

    # We scan the image for a QR code
    from pyzbar.pyzbar import decode
    payload = decode(image)[0]
    assert payload.data.startswith(b"HC1:")

    # The payload is prefixed with "HC1:" -> strip and base45 decode
    import base45
    payload = base45.b45decode(payload.data[4:].decode())

    # zlib decode
    import zlib
    payload = zlib.decompress(payload)

    # Now we have a signed CBOR data structure -> COSE message
    # Note: COSE is to CBOR what JOSE (JWT) is to JSON
    from cose.messages import CoseMessage
    cose_msg = CoseMessage.decode(payload)

    # We extract the KID of the certificate we need to verify the signature
    import cose.headers
    required_kid = cose_msg.get_attr(cose.headers.KID)

    # Now to verify the signature we have to find the right certifcate
    # The Austrian government provides an API:
    trustlist = await fetch_austria_data_and_verify("trustlist")
    for entry in trustlist["c"]:
        kid = entry["i"]
        cert = entry["c"]
        if kid == required_kid:
            break
    else:
        raise Exception("kid nto found")
    found_cert = cert

    # Now we convert to CERT to a COSE key
    # WARNING: we assume ES256 here but all other algorithms are allowed too
    from cryptography import x509
    from cose.keys import EC2Key
    cert = x509.load_der_x509_certificate(found_cert)
    public_key = cert.public_key()
    x = public_key.public_numbers().x.to_bytes(32, "big")
    y = public_key.public_numbers().y.to_bytes(32, "big")
    cose_key = EC2Key(crv='P_256', x=x, y=y, optional_params={'ALG': 'ES256'})

    # Now we verify the signature
    cose_msg.key = cose_key
    cose_msg.verify_signature()

    # Now we know it is valid, so decode the payload and pretty print
    # https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
    import cbor2
    import pprint
    hcert = cbor2.loads(cose_msg.payload)[-260][1]
    pprint.pprint(hcert)

    # Now we need to check if the HCERT can be used to go out and get a beer
    # This is done by combining the HCERT JSON with a so called
    # "Value Set" and the current time, then take a "Business Rule" and pass both
    # through an extension of JsonLogic called CertLogic.
    # If that process returns true for all rules then we can have a beer.
    valusets = await fetch_austria_data_and_verify("valuesets")
    rules = await fetch_austria_data_and_verify("rules")

    # convert the valuesets to something json/certlogic can work with
    import json
    value_sets_for_logic = {}
    for entry in valusets["v"]:
        v = json.loads(entry["v"])
        value_sets_for_logic[v["valueSetId"]] = list(v["valueSetValues"].keys())

    filtered_rules = []
    for entry in rules["r"]:
        r = json.loads(entry["r"])
        # Only for Austria and only "Eintrittstest"
        if r["Country"] == "AT" and r["Region"] == "ET":
            filtered_rules.append(r)

    from datetime import datetime, timezone

    validationClock = datetime.now(timezone.utc).isoformat()
    logic_data = {
        "payload": hcert,
        "external": {
            "valueSets": value_sets_for_logic,
            "validationClock": validationClock
        },
    }

    def certlogic(logic, data):
        # there is no good jsonlogic/certlogic library for python,
        # so shell out to node :(
        import subprocess
        import tempfile
        import json
        with tempfile.NamedTemporaryFile() as logic_file:
            logic_file.write(json.dumps(logic).encode())
            with tempfile.NamedTemporaryFile() as data_file:
                data_file.write(json.dumps(data).encode())
                data_file.flush()
                logic_file.flush()
                return json.loads(subprocess.check_output(["node", "./node_modules/certlogic-js/dist/cli.js", logic_file.name, data_file.name], text=True))

    ok = True
    for r in filtered_rules:
        result = certlogic(r["Logic"], logic_data)
        if not result:
            ok = False
        print(f"{'✅' if result else '❌'} [{r['Identifier']}] {r['Description'][0]['desc']}")

    print("~" * 40)
    print(("🍻" if ok else "❌") + " " + ("No beer for you" if not ok else "Cheers"))


if __name__ == "__main__":
    import asyncio
    asyncio.run(main("input1.pdf"))