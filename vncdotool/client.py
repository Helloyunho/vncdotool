"""
Twisted based VNC client protocol and factory

(c) 2010 Marc Sibson

MIT License
"""

import asyncio
import logging
import math
import socket
import time
from pathlib import Path
from struct import pack
from typing import IO, Any, List, Optional, TypeVar, Union
from PIL import Image

from . import rfb

TClient = TypeVar("TClient", bound="VNCDoToolClient")
TFile = Union[str, Path, IO[bytes]]

log = logging.getLogger(__name__)


KEYMAP = {
    "bsp": rfb.KEY_BackSpace,
    "tab": rfb.KEY_Tab,
    "return": rfb.KEY_Return,
    "enter": rfb.KEY_Return,
    "esc": rfb.KEY_Escape,
    "ins": rfb.KEY_Insert,
    "delete": rfb.KEY_Delete,
    "del": rfb.KEY_Delete,
    "home": rfb.KEY_Home,
    "end": rfb.KEY_End,
    "pgup": rfb.KEY_PageUp,
    "pgdn": rfb.KEY_PageDown,
    "left": rfb.KEY_Left,
    "up": rfb.KEY_Up,
    "right": rfb.KEY_Right,
    "down": rfb.KEY_Down,
    "slash": rfb.KEY_BackSlash,
    "bslash": rfb.KEY_BackSlash,
    "fslash": rfb.KEY_ForwardSlash,
    "spacebar": rfb.KEY_SpaceBar,
    "space": rfb.KEY_SpaceBar,
    "sb": rfb.KEY_SpaceBar,
    "f1": rfb.KEY_F1,
    "f2": rfb.KEY_F2,
    "f3": rfb.KEY_F3,
    "f4": rfb.KEY_F4,
    "f5": rfb.KEY_F5,
    "f6": rfb.KEY_F6,
    "f7": rfb.KEY_F7,
    "f8": rfb.KEY_F8,
    "f9": rfb.KEY_F9,
    "f10": rfb.KEY_F10,
    "f11": rfb.KEY_F11,
    "f12": rfb.KEY_F12,
    "f13": rfb.KEY_F13,
    "f14": rfb.KEY_F14,
    "f15": rfb.KEY_F15,
    "f16": rfb.KEY_F16,
    "f17": rfb.KEY_F17,
    "f18": rfb.KEY_F18,
    "f19": rfb.KEY_F19,
    "f20": rfb.KEY_F20,
    "lshift": rfb.KEY_ShiftLeft,
    "shift": rfb.KEY_ShiftLeft,
    "rshift": rfb.KEY_ShiftRight,
    "lctrl": rfb.KEY_ControlLeft,
    "ctrl": rfb.KEY_ControlLeft,
    "rctrl": rfb.KEY_ControlRight,
    "lmeta": rfb.KEY_MetaLeft,
    "meta": rfb.KEY_MetaLeft,
    "rmeta": rfb.KEY_MetaRight,
    "lalt": rfb.KEY_AltLeft,
    "alt": rfb.KEY_AltLeft,
    "ralt": rfb.KEY_AltRight,
    "scrlk": rfb.KEY_Scroll_Lock,
    "sysrq": rfb.KEY_Sys_Req,
    "numlk": rfb.KEY_Num_Lock,
    "caplk": rfb.KEY_Caps_Lock,
    "pause": rfb.KEY_Pause,
    "lsuper": rfb.KEY_Super_L,
    "super": rfb.KEY_Super_L,
    "rsuper": rfb.KEY_Super_R,
    "lhyper": rfb.KEY_Hyper_L,
    "hyper": rfb.KEY_Hyper_L,
    "rhyper": rfb.KEY_Hyper_R,
    "kp0": rfb.KEY_KP_0,
    "kp1": rfb.KEY_KP_1,
    "kp2": rfb.KEY_KP_2,
    "kp3": rfb.KEY_KP_3,
    "kp4": rfb.KEY_KP_4,
    "kp5": rfb.KEY_KP_5,
    "kp6": rfb.KEY_KP_6,
    "kp7": rfb.KEY_KP_7,
    "kp8": rfb.KEY_KP_8,
    "kp9": rfb.KEY_KP_9,
    "kpenter": rfb.KEY_KP_Enter,
}


class VNCDoException(Exception):
    pass


class AuthenticationError(VNCDoException):
    """VNC Server requires Authentication"""


RGB32 = rfb.PixelFormat(32, 24, False, True, 255, 255, 255, 0, 8, 16)
RGB24 = rfb.PixelFormat(24, 24, False, True, 255, 255, 255, 0, 8, 16)
BGR16 = rfb.PixelFormat(16, 16, False, True, 31, 63, 31, 11, 5, 0)
PF2IM = {
    RGB24: "RGB",
    RGB32: "RGBX",
    BGR16: "BGR;16",
    rfb.PixelFormat(24, 24, False, True, 255, 255, 255, 16, 8, 0): "BGR",
    rfb.PixelFormat(32, 24, False, True, 255, 255, 255, 16, 8, 0): "BGRX",
}


class VNCDoToolClient(rfb.RFBClient):
    encoding = rfb.Encoding.RAW
    x = 0
    y = 0
    buttons = 0
    screen: Optional[Image.Image] = None
    image_mode = PF2IM[rfb.PixelFormat()]

    cursor: Optional[Image.Image] = None
    cmask: Optional[Image.Image] = None

    SPECIAL_KEYS_US = '~!@#$%^&*()_+{}|:"<>?'
    MAX_DESKTOP_SIZE = 0x10000

    username: Optional[str] = None
    password: Optional[str] = None
    shared = True

    def __init__(self):
        super().__init__()
        self.updateCommited = asyncio.Event()
        self.pseudocursor = False
        self.nocursor = False
        self.pseudodesktop = True
        self.qemu_extended_key = True
        self.last_rect = True
        self.force_caps = False

    def _decodeKey(self, key: str) -> List[int]:
        if self.force_caps:
            if key.isupper() or key in self.SPECIAL_KEYS_US:
                key = "shift-%c" % key

        if len(key) == 1:
            keys = [key]
        else:
            keys = key.split("-")

        return [KEYMAP.get(k) or ord(k) for k in keys]

    async def pause(self, duration: float):
        await asyncio.sleep(duration)

    async def keyPress(self: TClient, key: str) -> TClient:
        """Send a key press to the server

        key: string: either [a-z] or a from KEYMAP
        """
        keys = self._decodeKey(key)
        log.debug("keyPress %s", keys)
        for k in keys:
            await self.keyEvent(k, down=True)
        for k in reversed(keys):
            await self.keyEvent(k, down=False)

        return self

    async def keyDown(self: TClient, key: str) -> TClient:
        keys = self._decodeKey(key)
        log.debug("keyDown %s", keys)
        for k in keys:
            await self.keyEvent(k, down=True)

        return self

    async def keyUp(self: TClient, key: str) -> TClient:
        keys = self._decodeKey(key)
        log.debug("keyUp %s", keys)
        for k in keys:
            await self.keyEvent(k, down=False)

        return self

    async def mousePress(self: TClient, button: int) -> TClient:
        """Send a mouse click at the last set position

        button: int: [1-n]

        """
        log.debug("mousePress %s", button)
        await self.mouseDown(button)
        await self.mouseUp(button)

        return self

    async def mouseDown(self: TClient, button: int) -> TClient:
        """Send a mouse button down at the last set position

        button: int: [1-n]

        """
        log.debug("mouseDown %s", button)
        self.buttons |= 1 << (button - 1)
        await self.pointerEvent(self.x, self.y, buttonmask=self.buttons)

        return self

    async def mouseUp(self: TClient, button: int) -> TClient:
        """Send mouse button released at the last set position

        button: int: [1-n]

        """
        log.debug("mouseUp %s", button)
        self.buttons &= ~(1 << (button - 1))
        await self.pointerEvent(self.x, self.y, buttonmask=self.buttons)

        return self

    async def captureScreen(self, fp: TFile, incremental: bool = False):
        """Save the current display to filename"""
        log.debug("captureScreen %s", fp)
        return self._capture(fp, incremental)

    async def captureRegion(
        self, fp: TFile, x: int, y: int, w: int, h: int, incremental: bool = False
    ):
        """Save a region of the current display to filename"""
        log.debug("captureRegion %s", fp)
        return self._capture(fp, incremental, x, y, x + w, y + h)

    async def refreshScreen(self: TClient, incremental: bool = False) -> TClient:
        self.updateCommited.clear()
        await self.framebufferUpdateRequest(incremental=incremental)
        await self.updateCommited.wait()
        return self

    async def _capture(self, fp: TFile, incremental: bool, *args: int):
        await self.refreshScreen(incremental)
        self._captureSave(fp, *args)

    def _captureSave(self: TClient, fp: TFile, *args: int) -> TClient:
        log.debug("captureSave %s", fp)
        assert self.screen is not None
        if args:
            capture = self.screen.crop(args)  # type: ignore[arg-type]
        else:
            capture = self.screen
        capture.save(fp)

        return self

    async def expectScreen(self: TClient, filename: str, maxrms: float = 0) -> TClient:
        """Wait until the display matches a target image

        filename: an image file to read and compare against
        maxrms: the maximum root mean square between histograms of the
                screen and target image
        """
        log.debug("expectScreen %s", filename)
        await self._expectFramebuffer(filename, 0, 0, maxrms)
        return self

    async def expectRegion(
        self: TClient, filename: str, x: int, y: int, maxrms: float = 0
    ) -> TClient:
        """Wait until a portion of the screen matches the target image

        The region compared is defined by the box
        (x, y), (x + image.width, y + image.height)
        """
        log.debug("expectRegion %s (%s, %s)", filename, x, y)
        await self._expectFramebuffer(filename, x, y, maxrms)
        return self

    async def _expectFramebuffer(self, filename: str, x: int, y: int, maxrms: float):
        image = Image.open(filename)
        w, h = image.size
        self.expected = image.histogram()

        await self._expectCompare((x, y, x + w, y + h), maxrms)

    async def _expectCompare(self, box: rfb.Rect, maxrms: float):
        incremental = False
        if self.screen:
            incremental = True
            image = self.screen.crop(box)

            hist = image.histogram()
            if len(hist) == len(self.expected):
                sum_ = sum((h - e) ** 2 for h, e in zip(hist, self.expected))
                rms = math.sqrt(sum_ / len(hist))

                log.debug("rms:%f maxrms:%f", rms, maxrms)
                if rms <= maxrms:
                    return

        await self.framebufferUpdateRequest(
            incremental=incremental
        )  # use box ~(x, y, w - x, h - y)?
        await self.updateCommited.wait()
        await self._expectCompare(box, maxrms)

    async def mouseMove(self: TClient, x: int, y: int) -> TClient:
        """Move the mouse pointer to position (x, y)"""
        log.debug("mouseMove %d,%d", x, y)
        self.x, self.y = x, y
        await self.pointerEvent(x, y, self.buttons)
        return self

    async def mouseDrag(self: TClient, x: int, y: int, step: int = 1) -> TClient:
        """Move the mouse point to position (x, y) in increments of step"""
        log.debug("mouseDrag %d,%d", x, y)
        if x < self.x:
            xsteps = range(self.x - step, x, -step)
        else:
            xsteps = range(self.x + step, x, step)

        if y < self.y:
            ysteps = range(self.y - step, y, -step)
        else:
            ysteps = range(self.y + step, y, step)

        for ypos in ysteps:
            await self.mouseMove(self.x, ypos)
            await asyncio.sleep(0.2)

        for xpos in xsteps:
            await self.mouseMove(xpos, self.y)
            await asyncio.sleep(0.2)

        await self.mouseMove(x, y)

        return self

    async def setImageMode(self) -> None:
        """Check support for PixelFormats announced by server or select client supported alternative."""
        try:
            self.image_mode = PF2IM[self.pixel_format]
        except LookupError:
            if self._version_server == (3, 889):  # Apple Remote Desktop
                pixel_format = BGR16
            else:
                pixel_format = RGB32

            await self.setPixelFormat(pixel_format)
            self.image_mode = PF2IM[pixel_format]

    #
    # base customizations
    #
    async def vncRequestPassword(self) -> None:
        if self.password is None:
            await self.disconnect()
            raise AuthenticationError("password required, but none provided")
        await self.sendPassword(self.password)

    async def vncConnectionMade(self) -> None:
        await self.setImageMode()
        encodings = [self.encoding]
        if self.pseudocursor or self.nocursor:
            encodings.append(rfb.Encoding.PSEUDO_CURSOR)
        if self.pseudodesktop:
            encodings.append(rfb.Encoding.PSEUDO_DESKTOP_SIZE)
        if self.last_rect:
            encodings.append(rfb.Encoding.PSEUDO_LAST_RECT)
        if self.qemu_extended_key:
            encodings.append(rfb.Encoding.PSEUDO_QEMU_EXTENDED_KEY_EVENT)
        await self.setEncodings(encodings)

    async def bell(self) -> None:
        log.info("ding")

    async def copy_text(self, text: str) -> None:
        log.info(f"clipboard copy {text!r}")

    async def paste(self: TClient, message: str) -> TClient:
        await self.clientCutText(message)
        return self

    async def updateRectangle(
        self, x: int, y: int, width: int, height: int, data: bytes
    ) -> None:
        # ignore empty updates
        if not data:
            return

        size = (width, height)
        if self.screen and (
            size[0] != self.screen.size[0] or size[1] != self.screen.size[1]
        ):
            await self.mouseMove(width, height)
            await self.mouseMove(0, 0)
        update = Image.frombytes("RGB", size, data, "raw", self.image_mode)
        if not self.screen:
            self.screen = update
        # track upward screen resizes, often occurs during os boot of VMs
        # When the screen is sent in chunks (as observed on VMWare ESXi), the canvas
        # needs to be resized to fit all existing contents and the update.
        elif self.screen.size[0] < (x + width) or self.screen.size[1] < (y + height):
            new_size = (
                max(x + width, self.screen.size[0]),
                max(y + height, self.screen.size[1]),
            )
            new_screen = Image.new("RGB", new_size, "black")
            new_screen.paste(self.screen, (0, 0))
            new_screen.paste(update, (x, y))
            self.screen = new_screen
        else:
            self.screen.paste(update, (x, y))

        await self.drawCursor()

    async def commitUpdate(self, rectangles: Optional[List[rfb.Rect]] = None) -> None:
        self.updateCommited.set()

    async def updateCursor(
        self, x: int, y: int, width: int, height: int, image: bytes, mask: bytes
    ) -> None:
        if self.nocursor:
            return

        if not width or not height:
            self.cursor = None

        self.cursor = Image.frombytes(
            "RGB", (width, height), image, "raw", self.image_mode
        )
        self.cmask = Image.frombytes("1", (width, height), mask)
        self.cfocus = x, y
        await self.drawCursor()

    async def drawCursor(self) -> None:
        if not self.cursor:
            return

        if not self.screen:
            return

        x = self.x - self.cfocus[0]
        y = self.y - self.cfocus[1]
        self.screen.paste(self.cursor, (x, y), self.cmask)

    async def updateDesktopSize(self, width: int, height: int) -> None:
        if not (
            0 <= width < self.MAX_DESKTOP_SIZE and 0 <= height < self.MAX_DESKTOP_SIZE
        ):
            raise ValueError((width, height))
        new_screen = Image.new("RGB", (width, height), "black")
        if self.screen:
            new_screen.paste(self.screen, (0, 0))
        self.screen = new_screen


class VMWareClient(VNCDoToolClient):
    SINGLE_PIXLE_UPDATE = pack(
        "!BxHHHHHixxxx",
        rfb.MsgS2C.FRAMEBUFFER_UPDATE,  # message-type
        # padding
        1,  # number-of-rectangles
        0,  # x-position
        0,  # y.position
        1,  # width
        1,  # height
        rfb.Encoding.RAW,  # encoding-type
        # pixel-data
    )

    async def dataReceived(self, data: bytes) -> None:
        # BUG: TCP is a *stream* orianted protocol with no *framing*.
        # Therefore there is no guarantee that these 20 bytes will arrive in one single chunk.
        # This might also match inside any other sequence if fragmentation by chance puts it at be start of a new packet.
        if (
            len(data) == 20
            and data[0] == self.SINGLE_PIXEL_UPDATE[0]
            and data[2:16] == self.SINGLE_PIXEL_UPDATE[2:16]
        ):
            await self.framebufferUpdateRequest()
            self._handler()
        else:
            await super().dataReceived(data)
