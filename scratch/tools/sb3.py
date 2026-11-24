"""Minimal, dependency-free Scratch 3 (.sb3) project builder.

Why this exists
---------------
Hand-placing 15k blocks in the editor is not a workflow; generating them is.
This module emits the same JSON that Scratch/TurboWarp writes, so a generator
script can turn an algorithm into a real, openable, runnable project id.

Only the block shapes an algorithm port needs are modelled: variables, lists,
procedures (warp), control flow, operators, and literal inputs.  Extensions
(pen, music, ...) are not used: a pure-arithmetic port needs none.

Number semantics worth remembering
----------------------------------
Scratch numbers are IEEE-754 doubles.  Every integer below 2**53 is exact, so a
32-bit word is representable exactly, and the ONLY thing missing from the
language is bitwise operators.  Division by a power of two is exact; `mod` is
JS `%`.  See sha256.py for how the ports work around the missing xor.
"""

import hashlib
import json
import zipfile

# input "type" tags used in the project.json schema
NUM = 4
POS = 5
POSINT = 6
INTEGER = 7
ANGLE = 8
COLOR = 9
STRING = 10
BROADCAST = 11

_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _squash(idx):
    out = ""
    for _ in range(20):
        out += _ALPHABET[idx % len(_ALPHABET)]
        idx //= len(_ALPHABET)
    return out


class _Ids:
    def __init__(self):
        self.n = 0

    def next(self):
        self.n += 1
        return _squash(self.n * 2654435761 % (62 ** 20))


# --------------------------------------------------------------------------
# input wrappers


class Rep:
    """A reporter block used where a value is expected."""

    def __init__(self, block_id):
        self.block_id = block_id


class Bool:
    """A boolean block used where a condition is expected."""

    def __init__(self, block_id):
        self.block_id = block_id


class Sub:
    """A block used as a C-shaped substack."""

    def __init__(self, block_id):
        self.block_id = block_id


# --------------------------------------------------------------------------


class Target:
    def __init__(self, project, name, is_stage=False):
        self.project = project
        self.name = name
        self.is_stage = is_stage
        self.blocks = {}
        self.variables = {}
        self.lists = {}
        self.broadcasts = {}
        self.comments = {}
        self.costumes = []
        self.sounds = []
        self._varname = {}
        self._listname = {}
        self._top = 0
        self._col = 0
        self.layer_order = 0
        self.size = 100

    # ---- declarations ---------------------------------------------------
    def var(self, name, value=0):
        if name not in self._varname:
            vid = self.project.ids.next()
            self._varname[name] = vid
            self.variables[vid] = [name, value]
        return self._varname[name]

    def lst(self, name, values=None):
        if name not in self._listname:
            lid = self.project.ids.next()
            self._listname[name] = lid
            self.lists[lid] = [name, list(values or [])]
        return self._listname[name]

    # ---- block emission -------------------------------------------------
    def emit(self, opcode, inputs=None, fields=None, mutation=None, shadow=False):
        bid = self.project.ids.next()
        blk = {
            "opcode": opcode,
            "next": None,
            "parent": None,
            "inputs": {},
            "fields": {},
            "shadow": shadow,
            "topLevel": False,
        }
        self.blocks[bid] = blk
        for key, val in (inputs or {}).items():
            blk["inputs"][key] = self._input(val)
        for key, val in (fields or {}).items():
            blk["fields"][key] = val
        if mutation is not None:
            blk["mutation"] = mutation
        return bid

    def _input(self, val):
        if isinstance(val, Rep):
            return [3, val.block_id, [NUM, "0"]]
        if isinstance(val, Bool):
            return [2, val.block_id]
        if isinstance(val, Sub):
            return [2, val.block_id]
        if isinstance(val, str) and val in self.blocks:
            # a reporter block id returned by an earlier emit() call
            return [3, val, [NUM, "0"]]
        if isinstance(val, bool):
            return [1, [NUM, "1" if val else "0"]]
        if isinstance(val, (int, float)):
            return [1, [NUM, _numstr(val)]]
        if isinstance(val, str):
            return [1, [STRING, val]]
        raise TypeError("bad input %r" % (val,))

    # ---- chaining -------------------------------------------------------
    def chain(self, *ids):
        ids = [i for i in ids if i is not None]
        for left, right in zip(ids, ids[1:]):
            self.blocks[left]["next"] = right
            self.blocks[right]["parent"] = left
        return ids[0] if ids else None

    def script(self, first, x=None, y=None):
        """Mark a block as the head of a top-level stack."""
        blk = self.blocks[first]
        blk["topLevel"] = True
        blk["x"] = self._col * 500 if x is None else x
        blk["y"] = self._top if y is None else y
        if y is None:
            self._top += 400
            if self._top > 20000:
                self._top = 0
                self._col += 1
        return first

    # ---- procedures -----------------------------------------------------
    def def_proc(self, proccode, argnames=(), warp=True):
        """Emit a procedure definition + prototype; return (def_id, body_start).

        body_start is the first emitted block of the signature, to be used as
        the head of the definition's script.
        """
        def_id = self.project.ids.next()
        proto_id = self.project.ids.next()
        argids = []
        inputs = {}
        for a in argnames:
            aid = self.project.ids.next()
            argids.append(aid)
            shadow_id = self.project.ids.next()
            self.blocks[shadow_id] = {
                "opcode": "argument_reporter_string_number",
                "next": None,
                "parent": proto_id,
                "inputs": {},
                "fields": {"VALUE": [a, None]},
                "shadow": True,
                "topLevel": False,
            }
            inputs[aid] = [1, shadow_id]
        mutation = {
            "tagName": "mutation",
            "children": [],
            "warp": "true" if warp else "false",
            "proccode": proccode,
            "argumentids": json.dumps(argids),
            "argumentnames": json.dumps(list(argnames)),
            "argumentdefaults": json.dumps(["" for _ in argnames]),
        }
        self.blocks[proto_id] = {
            "opcode": "procedures_prototype",
            "next": None,
            "parent": def_id,
            "inputs": inputs,
            "fields": {},
            "shadow": True,
            "topLevel": False,
            "mutation": mutation,
        }
        self.blocks[def_id] = {
            "opcode": "procedures_definition",
            "next": None,
            "parent": None,
            "inputs": {"custom_block": [2, proto_id]},
            "fields": {},
            "shadow": False,
            "topLevel": False,
        }
        self._procs[proccode] = (argnames, argids)
        return def_id, def_id

    def call_proc(self, proccode, values=()):
        argnames, argids = self._procs[proccode]
        inputs = {}
        for aid, val in zip(argids, values):
            inputs[aid] = val  # emit() encodes the input
        mutation = {
            "tagName": "mutation",
            "children": [],
            "warp": "true",
            "proccode": proccode,
            "argumentids": json.dumps(argids),
        }
        return self.emit("procedures_call", inputs=inputs, mutation=mutation)

    # ---- sugar ----------------------------------------------------------
    def getv(self, name):
        return self.emit("data_variable", fields={"VARIABLE": [name, self.var(name)]})

    def listlen(self, name):
        return self.emit("data_lengthoflist", fields={"LIST": [name, self.lst(name)]})

    def delete(self, name, index):
        return self.emit(
            "data_deleteoflist",
            inputs={"INDEX": index},
            fields={"LIST": [name, self.lst(name)]},
        )

    def setv(self, name, value):
        return self.emit(
            "data_setvariableto",
            inputs={"VALUE": value},
            fields={"VARIABLE": [name, self.var(name)]},
        )

    def changev(self, name, value):
        return self.emit(
            "data_changevariableby",
            inputs={"VALUE": value},
            fields={"VARIABLE": [name, self.var(name)]},
        )

    def addto(self, name, value):
        return self.emit(
            "data_addtolist",
            inputs={"ITEM": value},
            fields={"LIST": [name, self.lst(name)]},
        )

    def item(self, name, index):
        return self.emit(
            "data_itemoflist",
            inputs={"INDEX": index},
            fields={"LIST": [name, self.lst(name)]},
        )

    def itemnum(self, name, value):
        return self.emit(
            "data_itemnumoflist",
            inputs={"ITEM": value},
            fields={"LIST": [name, self.lst(name)]},
        )

    def replace(self, name, index, value):
        return self.emit(
            "data_replaceitemoflist",
            inputs={"INDEX": index, "ITEM": value},
            fields={"LIST": [name, self.lst(name)]},
        )

    def clear(self, name):
        return self.emit("data_deletealloflist", fields={"LIST": [name, self.lst(name)]})

    def arg(self, name):
        return self.emit("argument_reporter_string_number", fields={"VALUE": [name, None]})

    # ---- operators ------------------------------------------------------
    def add(self, a, b):
        return self.emit("operator_add", inputs={"NUM1": a, "NUM2": b})

    def sub(self, a, b):
        return self.emit("operator_subtract", inputs={"NUM1": a, "NUM2": b})

    def mul(self, a, b):
        return self.emit("operator_multiply", inputs={"NUM1": a, "NUM2": b})

    def div(self, a, b):
        return self.emit("operator_divide", inputs={"NUM1": a, "NUM2": b})

    def mod(self, a, b):
        return self.emit("operator_mod", inputs={"NUM1": a, "NUM2": b})

    def floor(self, a):
        return self.emit("operator_mathop", inputs={"NUM": a}, fields={"OPERATOR": ["floor", None]})

    def join(self, a, b):
        return self.emit("operator_join", inputs={"STRING1": a, "STRING2": b})

    def letter(self, i, s):
        return self.emit("operator_letter_of", inputs={"LETTER": i, "STRING": s})

    def length(self, s):
        return self.emit("operator_length", inputs={"STRING": s})

    def eq(self, a, b):
        return self.emit("operator_equals", inputs={"OPERAND1": a, "OPERAND2": b})

    def gt(self, a, b):
        return self.emit("operator_gt", inputs={"OPERAND1": a, "OPERAND2": b})

    def lt(self, a, b):
        return self.emit("operator_lt", inputs={"OPERAND1": a, "OPERAND2": b})

    def and_(self, a, b):
        return self.emit("operator_and", inputs={"OPERAND1": Bool(a), "OPERAND2": Bool(b)})

    def or_(self, a, b):
        return self.emit("operator_or", inputs={"OPERAND1": Bool(a), "OPERAND2": Bool(b)})

    def not_(self, a):
        return self.emit("operator_not", inputs={"OPERAND": Bool(a)})

    # ---- control --------------------------------------------------------
    def repeat(self, times, body_head):
        return self.emit("control_repeat", inputs={"TIMES": times, "SUBSTACK": Sub(body_head)})

    def if_(self, cond, body_head):
        return self.emit("control_if", inputs={"CONDITION": Bool(cond), "SUBSTACK": Sub(body_head)})

    def if_else(self, cond, then_head, else_head):
        return self.emit(
            "control_if_else",
            inputs={"CONDITION": Bool(cond), "SUBSTACK": Sub(then_head), "SUBSTACK2": Sub(else_head)},
        )

    def repeat_until(self, cond, body_head):
        return self.emit(
            "control_repeat_until", inputs={"CONDITION": Bool(cond), "SUBSTACK": Sub(body_head)}
        )

    def stop_script(self):
        return self.emit("control_stop", fields={"STOP_OPTION": ["this script", None]})

    def when_flag(self):
        return self.emit("event_whenflagclicked")

    def when_key(self, key):
        return self.emit("event_whenkeypressed", fields={"KEY_OPTION": [key, None]})

    def ask(self, question):
        return self.emit("sensing_askandwait", inputs={"QUESTION": question})

    def answer(self):
        return self.emit("sensing_answer")

    def timer(self):
        return self.emit("sensing_timer")

    def reset_timer(self):
        return self.emit("sensing_resettimer")

    def round(self, x):
        return self.emit("operator_round", inputs={"NUM": x})

    def think(self, text):
        return self.emit("looks_think", inputs={"MESSAGE": text})

    def say(self, text):
        return self.emit("looks_say", inputs={"MESSAGE": text})

    # ---- serialisation --------------------------------------------------
    def to_json(self):
        d = {
            "isStage": self.is_stage,
            "name": self.name,
            "variables": {k: list(v) for k, v in self.variables.items()},
            "lists": {k: [v[0], list(v[1])] for k, v in self.lists.items()},
            "broadcasts": self.broadcasts,
            "blocks": self.blocks,
            "comments": self.comments,
            "currentCostume": 0,
            "costumes": self.costumes,
            "sounds": self.sounds,
            "volume": 100,
            "layerOrder": self.layer_order,
        }
        if self.is_stage:
            d.update(
                {
                    "tempo": 60,
                    "videoTransparency": 50,
                    "videoState": "on",
                    "textToSpeechLanguage": None,
                }
            )
        else:
            d.update(
                {
                    "visible": True,
                    "x": 0,
                    "y": 0,
                    "size": self.size,
                    "direction": 90,
                    "draggable": False,
                    "rotationStyle": "all around",
                }
            )
        return d


class Project:
    def __init__(self):
        self.ids = _Ids()
        self.layer_order = 0
        self.size = 100
        self.targets = []
        self.monitors = []
        self.extensions = []
        self._stage = None
        self._assets = {}

    def _init_target(self, t):
        t._procs = getattr(t, "_procs", {})
        t.project = self
        return t

    def stage(self, name="Stage"):
        t = self._init_target(Target(self, name, is_stage=True))
        self._stage = t
        self.targets.append(t)
        t.layer_order = self.layer_order
        self.layer_order += 1
        return t

    def sprite(self, name):
        t = self._init_target(Target(self, name, is_stage=False))
        self.targets.append(t)
        t.layer_order = self.layer_order
        self.layer_order += 1
        return t

    def costume_png(self, target, name, path, rcx=None, rcy=None, bitmap_resolution=1):
        """A bitmap costume. The rotation centre defaults to the middle."""
        with open(path, "rb") as fh:
            data = fh.read()
        w, h = _png_size(data)
        md5 = hashlib.md5(data).hexdigest()
        self._assets[md5 + ".png"] = data
        target.costumes.append(
            {
                "name": name,
                "bitmapResolution": bitmap_resolution,
                "dataFormat": "png",
                "assetId": md5,
                "md5ext": md5 + ".png",
                "rotationCenterX": w / 2.0 / bitmap_resolution if rcx is None else rcx,
                "rotationCenterY": h / 2.0 / bitmap_resolution if rcy is None else rcy,
            }
        )

    def costume(self, target, name, svg, rcx=0, rcy=0):
        data = svg.encode("utf-8")
        md5 = hashlib.md5(data).hexdigest()
        self._assets[md5 + ".svg"] = data
        target.costumes.append(
            {
                "name": name,
                "bitmapResolution": 1,
                "dataFormat": "svg",
                "assetId": md5,
                "md5ext": md5 + ".svg",
                "rotationCenterX": rcx,
                "rotationCenterY": rcy,
            }
        )

    def monitor(self, target, varname, mode="large", x=5, y=5):
        self.monitors.append(
            {
                "id": target.var(varname),
                "mode": mode,
                "opcode": "data_variable",
                "params": {"VARIABLE": varname},
                "spriteName": None if target.is_stage else target.name,
                "value": 0,
                "width": 0,
                "height": 0,
                "x": x,
                "y": y,
                "visible": True,
                "sliderMin": 0,
                "sliderMax": 100,
                "isDiscrete": True,
            }
        )

    def save(self, path):
        project = {
            "targets": [t.to_json() for t in self.targets],
            "monitors": self.monitors,
            "extensions": self.extensions,
            "meta": {"semver": "3.0.0", "vm": "0.2.0", "agent": ""},
        }
        blob = json.dumps(project, separators=(",", ":")).encode("utf-8")
        # fixed timestamps: the same generator input must give the same bytes
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(_zipinfo("project.json"), blob)
            for name, data in sorted(self._assets.items()):
                z.writestr(_zipinfo(name), data)
        return len(blob)


def _png_size(data):
    """(width, height) from a PNG's IHDR, without decoding the image."""
    import struct

    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise ValueError("not a PNG")
    return struct.unpack(">II", data[16:24])


def _zipinfo(name):
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


def _numstr(v):
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v)


BLANK_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2" viewBox="0 0 2 2">'
    '<rect width="2" height="2" fill="none"/></svg>'
)
