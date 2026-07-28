from lxml import etree


def parse(payload: bytes):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(payload, parser)
