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

    # Set the key and verify the signature
    cose_msg.key = cose_key
    cose_msg.verify_signature()

    # Load the content and check that the checksum matches
    import cbor2
    import hashlib
    async with httpx.AsyncClient() as client:
        r = await client.get(f"https://dgc-trust.qr.gv.at/{thing}")
        r.raise_for_status()
        content = r.content
    if cbor2.loads(cose_msg.payload)[2] != hashlib.sha256(content).digest():
        raise Exception()

    # We can trust the content, so decode it
    return cbor2.loads(content)


async def certlogic(logic, data):
    # There is no good jsonlogic/certlogic library for python,
    # so shell out to node :(
    import asyncio
    import tempfile
    import json
    with tempfile.NamedTemporaryFile() as logic_file:
        logic_file.write(json.dumps(logic).encode())
        with tempfile.NamedTemporaryFile() as data_file:
            data_file.write(json.dumps(data).encode())
            data_file.flush()
            logic_file.flush()
            proc = await asyncio.create_subprocess_exec(
                "node", "./node_modules/certlogic-js/dist/cli.js",
                logic_file.name, data_file.name,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            (stdout_data, stderr_data) = await proc.communicate()
            return json.loads(stdout_data.decode())


async def check_rules(hcert):
    import pprint

    # Check if the HCERT can be used to go out and get a beer
    # This is done by combining the HCERT JSON with a so called
    # "Value Set" and the current time, then take a "Business Rule" and pass both
    # through an extension of JsonLogic called CertLogic.
    # If that process returns true for all rules then we can have a beer.
    valusets = await fetch_austria_data_and_verify("valuesets")
    rules = await fetch_austria_data_and_verify("rules")
    #pprint.pprint(rules)
    #pprint.pprint(valusets)

    # https://jsonlogic.com/
    # certlogic: https://github.com/ehn-dcc-development/dgc-business-rules/blob/main/certlogic/specification/README.md

    # convert the valuesets to something json/certlogic can work with
    import json
    value_sets_for_logic = {}
    for entry in valusets["v"]:
        v = json.loads(entry["v"])
        value_sets_for_logic[v["valueSetId"]] = list(v["valueSetValues"].keys())

    # filter the rules so we only get the ones for Austria and only "Eintrittstest"
    filtered_rules = []
    for entry in rules["r"]:
        r = json.loads(entry["r"])
        if r["Country"] == "AT" and r["Region"] == "ET":
            filtered_rules.append(r)
    #pprint.pprint(filtered_rules[1]["Description"])
    #pprint.pprint(filtered_rules[1]["Logic"])

    # Create the required input for certlogic
    from datetime import datetime, timezone
    validationClock = datetime.now(timezone.utc).isoformat()
    logic_data = {
        "payload": hcert,
        "external": {
            "valueSets": value_sets_for_logic,
            "validationClock": validationClock
        },
    }
    #pprint.pprint(logic_data, depth=3)

    # Check our input against all rules
    results = []
    for r in filtered_rules:
        logic_result = await certlogic(r["Logic"], logic_data)
        results.append((r, logic_result))

    # Now we print the result
    ok = True
    for rule, result in results:
        print(f"{'✅' if result else '❌'} [{rule['Identifier']}] {rule['Description'][0]['desc']}")
        if not result:
            ok = False
    print("~" * 40)
    print(("🍻" if ok else "❌") + " " + ("No beer for you" if not ok else "Cheers"))


async def main(filename: str):
    import pprint

    # We convert the input PDF to a PIL image
    from pdf2image import convert_from_path
    image = convert_from_path(filename)[0]
    #image.show()

    # We scan the image for a QR code
    from pyzbar.pyzbar import decode
    payload = decode(image)[0]
    assert payload.data.startswith(b"HC1:")
    #pprint.pprint(payload.data)

    # The payload is prefixed with "HC1:" -> strip and base45 decode
    import base45
    payload = base45.b45decode(payload.data[4:].decode())
    #pprint.pprint(payload)

    # zlib decode
    import zlib
    payload = zlib.decompress(payload)
    #pprint.pprint(payload)

    # Now we have a signed CBOR data structure -> COSE message
    # Note: COSE is to CBOR what JOSE (JWT) is to JSON
    from cose.messages import CoseMessage
    cose_msg = CoseMessage.decode(payload)
    #pprint.pprint({
    #    "uhdr": cose_msg.uhdr,
    #    "pdhr": cose_msg.phdr,
    #    "signature": cose_msg.signature,
    #    "payload": cose_msg.payload})

    # We extract the KID of the certificate we need to verify the signature
    import cose.headers
    required_kid = cose_msg.get_attr(cose.headers.KID)
    #pprint.pprint(required_kid)

    # To verify the signature we have to find the right certifcate
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
    #pprint.pprint(found_cert)

    # Parse the x509 cert
    from cryptography import x509
    from cose.keys import EC2Key
    cert = x509.load_der_x509_certificate(found_cert)
    #pprint.pprint(cert)

    # Convert the CERT to a COSE key and verify teh signature
    # WARNING: we assume ES256 here but all other algorithms are allowed too
    assert cose_msg.get_attr(cose.headers.Algorithm).fullname == "ES256"
    public_key = cert.public_key()
    x = public_key.public_numbers().x.to_bytes(32, "big")
    y = public_key.public_numbers().y.to_bytes(32, "big")
    cose_key = EC2Key(crv='P_256', x=x, y=y)
    cose_msg.key = cose_key
    cose_msg.verify_signature()

    # Now we know it is valid, so decode the payload and pretty print
    # https://ec.europa.eu/health/sites/default/files/ehealth/docs/covid-certificate_json_specification_en.pdf
    import cbor2
    import pprint
    payload = cbor2.loads(cose_msg.payload)
    #pprint.pprint(payload)

    # Get the inner content
    hcert = payload[-260][1]
    #pprint.pprint(hcert)

    await check_rules(hcert)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main("input/input1.pdf"))
