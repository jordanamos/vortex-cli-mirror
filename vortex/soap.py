from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from abc import ABC
from typing import Any
from typing import Literal
from typing import NamedTuple
from typing import NoReturn
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from vortex.models import PuakmaServer

logger = logging.getLogger("vortex")

_XSD_INTEGER: Literal["xsd:integer"] = "xsd:integer"
_XSD_STRING: Literal["xsd:string"] = "xsd:string"
_XSD_BOOLEAN: Literal["xsd:boolean"] = "xsd:boolean"
_XSD_BASE64_BINARY: Literal["xsd:base64Binary"] = "xsd:base64Binary"


class _PuakmaSOAPService(ABC):
    SERVICE_NAME: str

    def __init__(self, server: PuakmaServer, client: httpx.Client):
        self._server = server
        self._client = client

    @property
    def client(self) -> httpx.Client:
        return self._client

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.SERVICE_NAME}?WidgetExecute"


class _AsyncPuakmaSOAPService(_PuakmaSOAPService):
    def __init__(self, server: PuakmaServer, client: httpx.AsyncClient):
        super().__init__(server, client)

    @property
    def client(self) -> httpx.AsyncClient:
        return self._client


class _SOAPParam(NamedTuple):
    name: str
    xsi_type: Literal["xsd:integer", "xsd:string", "xsd:boolean", "xsd:base64Binary"]
    value: Any


class SOAPResponseParseError(Exception):
    def __init__(self, msg: str, response: ET.Element | None) -> None:
        e = f"Error parsing SOAP response: {msg}"
        if response and "Fault" in response[0].tag:
            e += "\n".join(
                [f"{ele.text.strip()}" for ele in response.findall(".//") if ele.text]
            )
        super().__init__(e)


class _SOAPClient:
    @staticmethod
    def _build_envelope(
        service_name: str, operation: str, params: list[_SOAPParam] | None = None
    ) -> str:
        ns = "soapenv"
        envelope = ET.Element(
            "{%s}Envelope" % ns,
            attrib={
                "xmlns:%s" % ns: "http://schemas.xmlsoap.org/soap/envelope/",
                "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
                "xmlns:soapenc": "http://schemas.xmlsoap.org/soap/encoding/",
            },
        )
        body = ET.SubElement(envelope, "{%s}Body" % ns)
        req = ET.SubElement(
            body,
            f"{{{ns}}}{operation}",
            {
                "xmlns:%s" % ns: "urn:%s" % service_name,
            },
        )
        if params:
            for param in params:
                e = ET.SubElement(req, param.name, attrib={"xsi:type": param.xsi_type})
                e.text = str(param.value)
        return ET.tostring(envelope, encoding="utf-8")

    @staticmethod
    def _parse_response(
        response_root: ET.Element, service_name: str, operation: str
    ) -> ET.Element:
        """
        Returns the root node of the expected SOAP response.
        If the response text is an xml document (CDATA), return the root
        node of the xml document. Otherwise the root node of the response
        element.

        Raises SOAPResponseParseError if unable to parse the response
        """

        def _error(msg: str, response: ET.Element | None) -> NoReturn:
            raise SOAPResponseParseError(msg, response)

        resp = response_root.find(".//{urn:" + service_name + "}" + operation)
        if not resp:
            _error("No matching response element", resp)

        return_node = resp[0]
        expected_tag = operation + "Return"
        if return_node.tag != expected_tag:
            _error(
                f"Expected Return Tag '{expected_tag}' got '{return_node.tag}'", resp
            )
        elif not return_node.text:
            _error(f"Response tag [{return_node.tag}] has no content", resp)
        try:
            # xml response - CDATA
            return ET.fromstring(return_node.text)
        except ET.ParseError:
            return return_node

    @classmethod
    def post(
        cls,
        service: _PuakmaSOAPService,
        operation: str,
        params: list[_SOAPParam] | None = None,
    ) -> ET.Element:
        """
        Builds and sends a SOAP envelope to the service endpoint and returns the parsed
        response element. Raises HTTPStatusError if one occurred
        """

        envelope = cls._build_envelope(service.SERVICE_NAME, operation, params)
        resp = service.client.post(
            service.endpoint,
            content=envelope,
            headers={"content-type": "text/xml"},
            timeout=10,
        )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text, parser=None)
        return cls._parse_response(tree, service.SERVICE_NAME, operation)

    @classmethod
    async def apost(
        cls,
        service: _AsyncPuakmaSOAPService,
        operation: str,
        params: list[_SOAPParam] | None = None,
    ) -> ET.Element:
        """
        Builds and sends a SOAP envelope to the service endpoint and returns the parsed
        response element. Raises HTTPStatusError if one occurred
        """

        envelope = cls._build_envelope(service.SERVICE_NAME, operation, params)
        resp = await service.client.post(
            service.endpoint,
            content=envelope,
            headers={"content-type": "text/xml"},
            timeout=10,
        )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text, parser=None)
        return cls._parse_response(tree, service.SERVICE_NAME, operation)


class AppDesigner(_PuakmaSOAPService):
    SERVICE_NAME: str = "AppDesigner"

    def get_application_xml(self, app_id: int) -> ET.Element:
        """Returns an XML representation of a puakma application."""
        operation = "getApplicationXml"
        params = [_SOAPParam("p1", _XSD_INTEGER, app_id)]
        resp = _SOAPClient.post(self, operation, params)
        return resp


class ServerDesigner(_AsyncPuakmaSOAPService):
    SERVICE_NAME: str = "ServerDesigner"

    async def ainitiate_connection(self) -> str:
        opertaion = "initiateConnection"
        resp = await _SOAPClient.apost(self, opertaion)
        return str(resp.text)


class DatabaseDesigner(_PuakmaSOAPService):
    SERVICE_NAME: str = "DatabaseDesigner"

    def execute_query(
        self,
        db_conn_id: int,
        query: str,
        is_update: bool = False,
    ) -> list[dict[str, Any]]:
        """Returns a list of dicts representing a return row"""
        operation = "executeQuery"
        params = [
            _SOAPParam("p1", _XSD_INTEGER, db_conn_id),
            _SOAPParam("p2", _XSD_STRING, query),
            _SOAPParam("p3", _XSD_BOOLEAN, is_update),
        ]
        resp = _SOAPClient.post(self, operation, params)
        col_lookup = [
            meta_row.attrib["name"] for meta_row in resp.findall(".//metadata")
        ]
        rows = []
        for row in resp.findall(".//row"):
            rows.append(
                {
                    col_lookup[int(col.attrib["index"]) - 1]: col.text
                    if col.text
                    else ""
                    for col in row
                }
            )

        return rows


class DownloadDesigner(_AsyncPuakmaSOAPService):
    SERVICE_NAME: str = "DownloadDesigner"

    async def aupload_design(
        self,
        design_id: int,
        base64data: str,
        do_source: bool = False,
        flush_cache: bool = True,
    ) -> bool:
        """Returns True if the design was uploaded successfully"""
        operation = "uploadDesign"
        params = [
            _SOAPParam("p1", _XSD_INTEGER, design_id),
            _SOAPParam("p2", _XSD_BOOLEAN, do_source),
            _SOAPParam("p3", _XSD_BASE64_BINARY, base64data),
            _SOAPParam("p4", _XSD_BOOLEAN, flush_cache),
        ]
        resp = await _SOAPClient.apost(self, operation, params)
        return resp.text == "true"
