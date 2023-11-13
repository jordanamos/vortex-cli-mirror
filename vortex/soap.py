from __future__ import annotations

import asyncio
import base64
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

from vortex import constants as C

if TYPE_CHECKING:
    from vortex.models import PuakmaServer
    from vortex.models import DesignObject


logger = logging.getLogger("vortex")

_XSD_INTEGER: Literal["xsd:integer"] = "xsd:integer"
_XSD_INT: Literal["xsd:int"] = "xsd:int"
_XSD_STRING: Literal["xsd:string"] = "xsd:string"
_XSD_BOOLEAN: Literal["xsd:boolean"] = "xsd:boolean"
_XSD_BASE64_BINARY: Literal["xsd:base64Binary"] = "xsd:base64Binary"
_XSI_NULL: Literal["xsi:null"] = "xsi:null"


class _SOAPParam(NamedTuple):
    name: str
    value: Any
    xsi_type: Literal[
        "xsd:integer",
        "xsd:string",
        "xsd:boolean",
        "xsd:base64Binary",
        "xsd:int",
    ] | None = None
    array_type: Literal["xsd:string"] | None = None


class SOAPResponseParseError(Exception):
    def __init__(self, msg: str, response: ET.Element) -> None:
        e = f"Error parsing SOAP response: {msg}"
        self.response = response
        super().__init__(e)


class _PuakmaSOAPService(ABC):
    name: str
    _sem = asyncio.Semaphore(40)
    _headers = {
        "content-type": "text/xml",
        "content-encoding": "gzip",
        "accept-encoding": "gzip",
        "user-agent": f"vortex-cli/{C.VERSION}",
    }

    def __init__(self, server: PuakmaServer):
        self._server = server

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def endpoint(self) -> str:
        return f"{self.server.base_soap_url}/{self.name}?WidgetExecute"

    @staticmethod
    def _add_params(request: ET.Element, params: list[_SOAPParam]) -> None:
        for param in params:
            if param.xsi_type:
                e = ET.SubElement(
                    request, param.name, attrib={"xsi:type": param.xsi_type}
                )
                e.text = str(param.value)
            elif param.array_type:
                array_type = f"{param.array_type}[{len(param.value)}]"
                e = ET.SubElement(
                    request, "soapenc:Array", attrib={"soapenc:arrayType": array_type}
                )
                for val in param.value:
                    v = ET.SubElement(e, "item")
                    v.text = str(val)
            else:
                raise ValueError(f"Unable to determine SOAP parameter type: {param}")

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
            self._add_params(req, params)

        return ET.tostring(envelope, encoding="utf-8")

    def _parse_response(self, response_root: ET.Element, operation: str) -> ET.Element:
        """
        Returns the root node of the expected SOAP response.
        If the response text is an xml document (CDATA), return the root
        node of the xml document. Otherwise the root node of the response
        element.

        Raises SOAPResponseParseError if unable to parse the response
        """

        def _error(msg: str) -> NoReturn:
            raise SOAPResponseParseError(msg, response_root)

        resp = response_root.find(".//{urn:" + self.name + "}" + operation)
        if resp is None:
            _error("No matching response element")
        try:
            return_node = resp[0]
        except IndexError:
            return_node = resp
        else:
            expected_tag = f"{operation}Return"
            if return_node.tag != expected_tag:
                _error(
                    f"Expected Return Tag '{expected_tag}' got '{return_node.tag}'",
                )

        # Potentially a void return type
        if not return_node.text:
            return return_node
            # _error(f"Response tag [{return_node.tag}] has no content")

        try:
            # xml response - CDATA
            return ET.fromstring(return_node.text)
        except ET.ParseError:
            return return_node

    def _post(
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
            headers=self._headers,
            timeout=20,
        )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text, parser=None)
        return self._parse_response(tree, operation)

    async def _apost(
        self,
        operation: str,
        params: list[_SOAPParam] | None = None,
        *,
        timeout: int = 20,
    ) -> ET.Element:
        """
        Builds and sends a SOAP envelope to the service endpoint and returns the parsed
        response element. Raises HTTPStatusError if one occurred
        """

        envelope = self._build_envelope(operation, params)
        async with self._sem:
            resp = await self.server._aclient.post(
                self.endpoint,
                content=gzip.compress(envelope),
                headers=self._headers,
                timeout=timeout,
            )
        resp.raise_for_status()
        tree = ET.fromstring(resp.text, parser=None)
        return self._parse_response(tree, operation)


class AppDesigner(_PuakmaSOAPService):
    name = "AppDesigner"

    def save_application(
        self,
        app_id: int,
        group: str,
        name: str,
        inheritfrom: str | None,
        templatename: str | None,
        description: str | None,
    ) -> int:
        """Creates (if app id == -1) or updates an application"""
        operation = "saveApplication"
        params = [
            _SOAPParam("p1", app_id, _XSD_INTEGER),
            _SOAPParam("p2", group, _XSD_STRING),
            _SOAPParam("p3", name, _XSD_STRING),
            _SOAPParam("p4", inheritfrom or "", _XSD_STRING),
            _SOAPParam("p5", templatename or "", _XSD_STRING),
            _SOAPParam("p6", description or "", _XSD_STRING),
        ]
        resp = self._post(operation, params)
        return int(resp.text) if resp.text else -1

    async def aget_application_xml(self, app_id: int) -> ET.Element:
        """Returns an XML representation of a puakma application."""
        operation = "getApplicationXml"
        params = [_SOAPParam("p1", app_id, _XSD_INTEGER)]
        resp = await self._apost(operation, params)
        return resp

    async def aupdate_design_object(
        self,
        obj: DesignObject,
    ) -> int:
        """
        Updates or creates (if obj.id == -1) the design object on the server.
        To update the design/source data use DownloadDesigner.aupload_design()
        Returns the ID of the design_object created or updated or -1 if unsuccessful
        """
        operation = "updateDesignObject"
        params = [
            _SOAPParam("p1", obj.id, _XSD_INTEGER),
            _SOAPParam("p2", obj.app.id, _XSD_INTEGER),
            _SOAPParam("p3", obj.name, _XSD_STRING),
            _SOAPParam("p4", obj.design_type.value, _XSD_INT),
            _SOAPParam("p5", obj.content_type, _XSD_STRING),
            _SOAPParam("p6", obj.comment if obj.comment else "", _XSD_STRING),
            _SOAPParam("p7", "", _XSD_STRING),
            _SOAPParam("p8", obj.inherit_from if obj.inherit_from else "", _XSD_STRING),
        ]

        resp = await self._apost(operation, params)
        id_ = int(resp.text if resp.text else -1)
        obj.id = id_
        return id_

    def save_keyword(
        self,
        app_id: int,
        keyword_id: int,
        name: str,
        data: list[str],
    ) -> int:
        operation = "saveKeyword"
        params = [
            _SOAPParam("p1", app_id, _XSD_INT),
            _SOAPParam("p2", keyword_id, _XSD_INTEGER),
            _SOAPParam("p3", name, _XSD_STRING),
            _SOAPParam("p4", data, array_type=_XSD_STRING),
        ]
        resp = self._post(operation, params)
        return int(resp.text) if resp.text else -1

    async def aremove_design_object(self, design_object_id: int) -> None:
        operation = "removeDesignObject"
        params = [_SOAPParam("p1", design_object_id, _XSD_INTEGER)]
        await self._apost(operation, params)

    async def aadd_design_object_param(
        self,
        design_object_id: int,
        param_name: Literal[
            "OpenAction",
            "SaveAction",
            "ParentPage",
        ],
        param_value: str,
    ) -> None:
        operation = "addDesignObjectParam"
        params = [
            _SOAPParam("p1", design_object_id, _XSD_INTEGER),
            _SOAPParam("p2", param_name, _XSD_STRING),
            _SOAPParam("p3", param_value, _XSD_STRING),
        ]
        await self._apost(operation, params)


class ServerDesigner(_PuakmaSOAPService):
    name = "ServerDesigner"

    async def ainitiate_connection(self) -> str:
        opertaion = "initiateConnection"
        resp = await self._apost(opertaion)
        logger.info(f"Connected to {self.server.host}...")
        return str(resp.text)

    def execute_command(self, command: str) -> str | None:
        operation = "executeCommand"
        params = [_SOAPParam("p1", command, _XSD_STRING)]
        resp = self._post(operation, params)
        return resp.text


class DatabaseDesigner(_PuakmaSOAPService):
    name = "DatabaseDesigner"

    async def aexecute_query(
        self,
        db_conn_id: int,
        query: str,
        is_update: bool = False,
    ) -> list[dict[str, Any]]:
        """Returns a list of dicts representing a return row"""
        operation = "executeQuery"
        params = [
            _SOAPParam("p1", db_conn_id, _XSD_INTEGER),
            _SOAPParam("p2", query, _XSD_STRING),
            _SOAPParam("p3", is_update, _XSD_BOOLEAN),
        ]
        resp = await self._apost(operation, params)
        col_lookup = [
            meta_row.attrib["name"] for meta_row in resp.findall(".//metadata")
        ]
        ret = []
        for row in resp.findall(".//row"):
            ret.append(
                {
                    col_lookup[int(col.attrib["index"]) - 1]: col.text
                    if col.text
                    else ""
                    for col in row
                }
            )
        return ret

    def execute_query(
        self,
        db_conn_id: int,
        query: str,
        is_update: bool = False,
    ) -> Generator[dict[str, Any], None, None]:
        """Returns a Generator of dicts representing a return row"""
        operation = "executeQuery"
        params = [
            _SOAPParam("p1", db_conn_id, _XSD_INTEGER),
            _SOAPParam("p2", query, _XSD_STRING),
            _SOAPParam("p3", is_update, _XSD_BOOLEAN),
        ]
        resp = self._post(operation, params)
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
            _SOAPParam("p1", design_id, _XSD_INTEGER),
            _SOAPParam("p2", do_source, _XSD_BOOLEAN),
            _SOAPParam("p3", base64data, _XSD_BASE64_BINARY),
            _SOAPParam("p4", flush_cache, _XSD_BOOLEAN),
        ]
        resp = await self._apost(operation, params)
        return resp.text == "true"

    async def adownload_pmx(
        self,
        app_id: int,
        include_source: bool = False,
    ) -> bytes:
        """Returns bytes xml"""
        operation = "downloadPmx"
        params = [
            _SOAPParam("p1", app_id, _XSD_INTEGER),
            _SOAPParam("p2", include_source, _XSD_BOOLEAN),
        ]
        # This operation takes a while for big applications, set timeout to 100
        resp = await self._apost(operation, params, timeout=100)
        if resp.text is not None:
            return base64.b64decode(resp.text)
        else:
            return b""

    def upload_pmx(self, app_group: str, app_name: str, pmx_file: bytes) -> int:
        operation = "uploadPmx"
        b64pmx = str(base64.b64encode(pmx_file), "utf-8")
        params = [
            _SOAPParam("p1", app_group, _XSD_STRING),
            _SOAPParam("p2", app_name, _XSD_STRING),
            _SOAPParam("p3", b64pmx, _XSD_BASE64_BINARY),
        ]
        resp = self._post(operation, params)
        return int(resp.text) if resp.text else -1
