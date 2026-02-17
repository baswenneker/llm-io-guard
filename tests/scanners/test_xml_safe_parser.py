"""Tests for the XmlSafeParser."""

from llm_io_guard.models import Action
from llm_io_guard.scanners.xml_safe_parser import XmlSafeParser


async def test_non_xml_passes():
    scanner = XmlSafeParser()
    result = await scanner.ascan("Just some plain text.")
    assert result.action == Action.PASS
    assert result.description == "Content is not XML, skipping"
    assert result.details["sanitized_content"] == "Just some plain text."


async def test_valid_xml_passes():
    scanner = XmlSafeParser()
    xml = '<?xml version="1.0"?><root><item>Hello</item></root>'
    result = await scanner.ascan(xml)
    assert result.action == Action.PASS
    assert "safely" in result.description
    assert result.details["sanitized_content"] == xml


async def test_xxe_blocked():
    scanner = XmlSafeParser()
    xxe_xml = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE foo ["
        '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
        "]>"
        "<root>&xxe;</root>"
    )
    result = await scanner.ascan(xxe_xml)
    assert result.action == Action.BLOCK
    assert result.confidence == 1.0
    assert "Malicious XML" in result.description


async def test_billion_laughs_blocked():
    scanner = XmlSafeParser()
    billion_laughs = (
        '<?xml version="1.0"?>'
        "<!DOCTYPE lolz ["
        '  <!ENTITY lol "lol">'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        '  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
        "]>"
        "<root>&lol4;</root>"
    )
    result = await scanner.ascan(billion_laughs)
    assert result.action == Action.BLOCK
    assert result.confidence == 1.0


async def test_malformed_xml_passes():
    scanner = XmlSafeParser()
    bad_xml = '<?xml version="1.0"?><root><unclosed>'
    result = await scanner.ascan(bad_xml)
    assert result.action == Action.PASS
    assert "Malformed" in result.description
    assert result.details["sanitized_content"] == bad_xml


async def test_xml_content_type_triggers_parsing():
    scanner = XmlSafeParser()
    result = await scanner.ascan("<root>data</root>", metadata={"content_type": "text/xml"})
    assert result.action == Action.PASS
    assert "safely" in result.description


async def test_scanner_name_and_tier():
    scanner = XmlSafeParser()
    assert scanner.name == "xml_safe_parser"
    assert scanner.tier == 1
