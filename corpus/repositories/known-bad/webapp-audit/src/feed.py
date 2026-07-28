from lxml import etree


def parse(payload: bytes):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(payload, parser)
