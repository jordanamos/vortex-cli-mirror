from __future__ import annotations

import asyncio
import gzip
import logging
import xml.etree.ElementTree as ET
from abc import ABC
from collections.abc import Generator
from typing import Any
from typing import Literal
from typing import NamedTuple
from typing import NoReturn
from typing import TYPE_CHECKING

from vortex.util import VERSION

if TYPE_CHECKING:
    from vortex.models import PuakmaServer
    from vortex.models import DesignObject

logger = logging.getLogger("vortex")

_XSD_INTEGER: Literal["xsd:integer"] = "xsd:integer"
_XSD_INT: Literal["xsd:int"] = "xsd:int"
_XSD_STRING: Literal["xsd:string"] = "xsd:string"
_XSD_BOOLEAN: Literal["xsd:boolean"] = "xsd:boolean"
_XSD_BASE64_BINARY: Literal["xsd:base64Binary"] = "xsd:base64Binary"


class _SOAPParam(NamedTuple):
    name: str
    xsi_type: Literal[
        "xsd:integer", "xsd:string", "xsd:boolean", "xsd:base64Binary", "xsd:int"
    ]
    value: Any


class SOAPResponseParseError(Exception):
    def __init__(self, msg: str, response: ET.Element | None) -> None:
        e = f"Error parsing SOAP response [{response}]: {msg}"
        if response and "Fault" in response[0].tag:
            e += "\n".join(
                [f"{ele.text.strip()}" for ele in response.findall(".//") if ele.text]
            )
        super().__init__(e)


class _PuakmaSOAPService(ABC):
    name: str
    sem = asyncio.Semaphore(40)
    headers = {
        "content-type": "text/xml",
        "content-encoding": "gzip",
        "accept-encoding": "gzip",
        "user-agent": f"vortex-cli/{VERSION}",
    }

    def __init__(self, server: PuakmaServer):
        self._server = server

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.name}?WidgetExecute"

    def _build_envelope(
        self, operation: str, params: list[_SOAPParam] | None = None
    ) -> bytes:
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
                "xmlns:%s" % ns: "urn:%s" % self.name,
            },
        )
        if params:
            for param in params:
                e = ET.SubElement(req, param.name, attrib={"xsi:type": param.xsi_type})
                e.text = str(param.value)
        return ET.tostring(envelope, encoding="utf-8")

    def _parse_response(self, response_root: ET.Element, operation: str) -> ET.Element:
        """
        Returns the root node of the expected SOAP response.
        If the response text is an xml document (CDATA), return the root
        node of the xml document. Otherwise the root node of the response
        element.

        Raises SOAPResponseParseError if unable to parse the response
        """

        def _error(msg: str, response: ET.Element | None) -> NoReturn:
            raise SOAPResponseParseError(msg, response)

        resp = response_root.find(".//{urn:" + self.name + "}" + operation)
        if resp is None:
            _error("No matching response element", resp)
        try:
            return_node = resp[0]
        except IndexError:
            return_node = resp
        else:
            expected_tag = f"{operation}Return"
            if return_node.tag != expected_tag:
                _error(
                    f"Expected Return Tag '{expected_tag}' got '{return_node.tag}'",
                    resp,
                )
        if not return_node.text:
            _error(f"Response tag [{return_node.tag}] has no content", resp)
        try:
            # xml response - CDATA
            return ET.fromstring(return_node.text)
        except ET.ParseError:
            return return_node

    def post(
        self,
        operation: str,
        params: list[_SOAPParam] | None = None,
    ) -> ET.Element:
        """
        Builds and sends a SOAP envelope to the service endpoint and returns the parsed
        response element. Raises HTTPStatusError if one occurred
        """
        envelope = self._build_envelope(operation, params)
        resp = self.server._client.post(
            self.endpoint,
            content=gzip.compress(envelope),
            headers=self.headers,
            timeout=20,
        )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text, parser=None)
        return self._parse_response(tree, operation)

    async def apost(
        self,
        operation: str,
        params: list[_SOAPParam] | None = None,
    ) -> ET.Element:
        """
        Builds and sends a SOAP envelope to the service endpoint and returns the parsed
        response element. Raises HTTPStatusError if one occurred
        """

        envelope = self._build_envelope(operation, params)
        async with self.sem:
            resp = await self.server._aclient.post(
                self.endpoint,
                content=gzip.compress(envelope),
                headers=self.headers,
                timeout=20,
            )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text, parser=None)
        return self._parse_response(tree, operation)


class AppDesigner(_PuakmaSOAPService):
    name = "AppDesigner"

    def get_application_xml(self, app_id: int) -> ET.Element:
        """Returns an XML representation of a puakma application."""
        operation = "getApplicationXml"
        params = [_SOAPParam("p1", _XSD_INTEGER, app_id)]
        resp = self.post(operation, params)
        return resp

    async def aupdate_design_object(
        self,
        obj: DesignObject,
    ) -> int:
        """
        Updates the design object with the given id with the values provided.
        If design_object_id is None (the default), then a new design object is created.
        Returns the ID of the design_object created or updated or -1 if unsuccessful
        """
        operation = "updateDesignObject"
        params = [
            _SOAPParam("p1", _XSD_INTEGER, obj.id),
            _SOAPParam("p2", _XSD_INTEGER, obj.app.id),
            _SOAPParam("p3", _XSD_STRING, obj.name),
            _SOAPParam("p4", _XSD_INT, obj.design_type.value),
            _SOAPParam("p5", _XSD_STRING, obj.content_type),
            _SOAPParam("p6", _XSD_STRING, obj.comment),
            _SOAPParam("p7", _XSD_STRING, ""),  # 'options' holds scheduling data
            _SOAPParam("p8", _XSD_STRING, obj.inherit_from),
        ]

        resp = await self.apost(operation, params)
        id_ = int(resp.text if resp.text else -1)
        obj.id = id_
        return id_

    def update_design_object(
        self,
        obj: DesignObject,
    ) -> int:
        """
        Updates the design object with the given id with the values provided.
        If design_object_id is None (the default), then a new design object is created.
        Returns the ID of the design_object created or updated or -1 if unsuccessful
        """
        operation = "updateDesignObject"
        params = [
            _SOAPParam("p1", _XSD_INTEGER, obj.id),
            _SOAPParam("p2", _XSD_INTEGER, obj.app.id),
            _SOAPParam("p3", _XSD_STRING, obj.name),
            _SOAPParam("p4", _XSD_INT, obj.design_type.value),
            _SOAPParam("p5", _XSD_STRING, obj.content_type),
            _SOAPParam("p6", _XSD_STRING, obj.comment),
            _SOAPParam("p7", _XSD_STRING, ""),  # 'options' holds scheduling data
            _SOAPParam("p8", _XSD_STRING, obj.inherit_from),
        ]

        resp = self.post(operation, params)
        id_ = int(resp.text if resp.text else -1)
        obj.id = id_
        return id_

    async def aremove_design_object(self, design_object_id: int) -> None:
        operation = "removeDesignObject"
        params = [_SOAPParam("p1", _XSD_INTEGER, design_object_id)]
        await self.apost(operation, params)

    def remove_design_object(self, design_object_id: int) -> None:
        """
        Remove a Design Objects.
        This Operation has a 'void' return type i.e. no way to know if successful (sad)
        """
        operation = "removeDesignObject"
        params = [_SOAPParam("p1", _XSD_INTEGER, design_object_id)]
        self.post(operation, params)


class ServerDesigner(_PuakmaSOAPService):
    name = "ServerDesigner"

    async def ainitiate_connection(self) -> str:
        opertaion = "initiateConnection"
        resp = await self.apost(opertaion)
        return str(resp.text)

    async def aget_last_log_items(
        self, limit_items: int = 5, last_log_id: int | None = None
    ) -> list[dict[str, str]]:
        assert limit_items >= 0
        if limit_items > 20:
            limit_items = 20
        operation = "getLastLogItems"
        params = [
            _SOAPParam("p1", _XSD_INTEGER, limit_items),
            _SOAPParam("p2", _XSD_INTEGER, last_log_id),
        ]
        resp = await self.apost(operation, params)
        return [log.attrib for log in resp.findall(".//logItem")]


class DatabaseDesigner(_PuakmaSOAPService):
    name = "DatabaseDesigner"

    def execute_query(
        self,
        db_conn_id: int,
        query: str,
        is_update: bool = False,
    ) -> Generator[dict[str, Any], None, None]:
        """Returns a list of dicts representing a return row"""
        operation = "executeQuery"
        params = [
            _SOAPParam("p1", _XSD_INTEGER, db_conn_id),
            _SOAPParam("p2", _XSD_STRING, query),
            _SOAPParam("p3", _XSD_BOOLEAN, is_update),
        ]
        resp = self.post(operation, params)
        col_lookup = [
            meta_row.attrib["name"] for meta_row in resp.findall(".//metadata")
        ]
        for row in resp.findall(".//row"):
            yield {
                col_lookup[int(col.attrib["index"]) - 1]: col.text if col.text else ""
                for col in row
            }


class DownloadDesigner(_PuakmaSOAPService):
    name = "DownloadDesigner"

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
        resp = await self.apost(operation, params)
        return resp.text == "true"
