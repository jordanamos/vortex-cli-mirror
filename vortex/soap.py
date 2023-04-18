from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from typing import NamedTuple
from typing import NoReturn
from typing import Protocol
from typing import TYPE_CHECKING

from requests import HTTPError
from requests import Session

if TYPE_CHECKING:
    from vortex.models import PuakmaServer

XSD_INTEGER = "xsd:integer"
XSD_STRING = "xsd:string"
XSD_BOOLEAN = "xsd:boolean"
XSD_BASE64_BINARY = "xsd:base64Binary"


class PuakmaSOAPService(Protocol):
    SERVICE_NAME: str

    def __init__(self, server: PuakmaServer, session: Session):
        ...

    @property
    def session(self) -> Session:
        ...

    @property
    def server(self) -> PuakmaServer:
        ...

    @property
    def endpoint(self) -> str:
        ...


class _SOAPParam(NamedTuple):
    name: str
    xsi_type: str
    value: Any


class SOAPResponseParseError(Exception):
    """Raised when unable to parse SOAP response to xml"""

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
        request = ET.SubElement(
            body,
            f"{{{ns}}}{operation}",
            {
                "xmlns:%s" % ns: "urn:%s" % service_name,
            },
        )
        if params:
            for param in params:
                e = ET.SubElement(
                    request, param.name, attrib={"xsi:type": param.xsi_type}
                )
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
        service: PuakmaSOAPService,
        operation: str,
        params: list[_SOAPParam] | None = None,
    ) -> ET.Element:
        """
        Builds and sends a SOAP envelope to the URL and returns the parsed
        response element. Raises HTTP Error if the status code is not 200
        (201 etc. also as we are not yet expecting those?)
        """

        envelope = cls._build_envelope(service.SERVICE_NAME, operation, params)
        resp = service.session.post(
            service.endpoint,
            data=envelope,
            headers={"content-type": "text/xml"},
            timeout=20,
        )
        if resp.status_code != 200:
            msg = f"{resp.status_code} {resp.reason} for url: '{resp.url}'"
            raise HTTPError(msg)
        tree = ET.fromstring(resp.text, parser=None)
        return cls._parse_response(tree, service.SERVICE_NAME, operation)


class AppDesigner:
    """App Service"""

    SERVICE_NAME = "AppDesigner"

    def __init__(self, server: PuakmaServer, session: Session) -> None:
        self._server = server
        self._session = session

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def session(self) -> Session:
        return self._session

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.SERVICE_NAME}?WidgetExecute"

    def get_application_xml(self, app_id: int) -> ET.Element:
        """
        Returns an XML representation of a puakma application.
        Raises a ValueError if it doesnt exist
        """
        operation = "getApplicationXml"
        params = [_SOAPParam("p1", XSD_INTEGER, app_id)]
        resp = _SOAPClient.post(self, operation, params)
        return resp


class ServerDesigner:
    """Server Service"""

    SERVICE_NAME = "ServerDesigner"

    def __init__(self, server: PuakmaServer, session: Session) -> None:
        self._server = server
        self._session = session

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def session(self) -> Session:
        return self._session

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.SERVICE_NAME}?WidgetExecute"

    def get_server_info(self) -> ET.Element:
        operation = "getServerInfo"
        return _SOAPClient.post(self, operation)


class DatabaseDesigner:
    """Database Service"""

    SERVICE_NAME = "DatabaseDesigner"

    def __init__(self, server: PuakmaServer, session: Session) -> None:
        self._server = server
        self._session = session

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def session(self) -> Session:
        return self._session

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.SERVICE_NAME}?WidgetExecute"

    def execute_query(
        self,
        db_conn_id: int,
        query: str,
        is_update: bool = False,
    ) -> list[dict[str, Any]]:
        """Returns a list of dicts representing a return row"""
        operation = "executeQuery"
        params = [
            _SOAPParam("p1", XSD_INTEGER, db_conn_id),
            _SOAPParam("p2", XSD_STRING, query),
            _SOAPParam("p3", XSD_BOOLEAN, is_update),
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


class DownloadDesigner:
    """Download Service"""

    SERVICE_NAME = "DownloadDesigner"

    def __init__(self, server: PuakmaServer, session: Session) -> None:
        self._server = server
        self._session = session

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def session(self) -> Session:
        return self._session

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.SERVICE_NAME}?WidgetExecute"

    def upload_design(
        self,
        design_id: int,
        base64data: str,
        do_source: bool = False,
        flush_cache: bool = True,
    ) -> bool:
        """Returns True if the design was uploaded"""
        operation = "uploadDesign"
        params = [
            _SOAPParam("p1", XSD_INTEGER, design_id),
            _SOAPParam("p2", XSD_BOOLEAN, do_source),
            _SOAPParam("p3", XSD_BASE64_BINARY, base64data),
            _SOAPParam("p4", XSD_BOOLEAN, flush_cache),
        ]
        resp = _SOAPClient.post(self, operation, params)
        return resp.text == "true"
