# SnapDramas Burp Extension
#
# Burp Suite Jython extension for SnapDramas traffic.
# - AES/ECB/PKCS5Padding + Base64
# - Decrypt request/response bodies in a custom editor tab
# - Edit plaintext, then re-encrypt on send
#
# Compatible with Jython 2.7 in Burp.

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec
from java.util import Base64
from java.lang import String
from java.awt import BorderLayout, FlowLayout, Dimension
from javax.swing import JPanel, JLabel, JScrollPane, JTextArea, JButton, JCheckBox
from java.io import PrintWriter
import re


KEY = "ipB7OHxAmJ9Qa1Lf38X1bP71zJMe4Yw6"
TRANSFORMATION = "AES/ECB/PKCS5Padding"
TAB_NAME = "SnapDramas AES"
DATA_FIELD = "data"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_text(value):
    if value is None:
        return None
    try:
        return String(value).toString()
    except Exception:
        try:
            return str(value)
        except Exception:
            return None


def _clean_b64(value):
    text = _to_text(value)
    if text is None:
        return None
    return re.sub(r"[^A-Za-z0-9+/=]", "", text).strip()


def _json_unescape(s):
    if s is None:
        return None
    s = s.replace('\\\\', '\\')
    s = s.replace('\\"', '"')
    s = s.replace('\\/', '/')
    s = s.replace('\\b', '\b')
    s = s.replace('\\f', '\f')
    s = s.replace('\\n', '\n')
    s = s.replace('\\r', '\r')
    s = s.replace('\\t', '\t')
    return s


def _json_escape(s):
    if s is None:
        return None
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('\b', '\\b')
    s = s.replace('\f', '\\f')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')
    return s


def _pretty_json(text):
    if text is None:
        return None
    t = _to_text(text)
    if t is None:
        return None
    t = t.strip()
    if not t.startswith('{') and not t.startswith('['):
        return t

    out = []
    indent = 0
    in_string = False
    escape = False

    for ch in t:
        if escape:
            out.append(ch)
            escape = False
            continue
        if ch == '\\':
            out.append(ch)
            if in_string:
                escape = True
            continue
        if ch == '"':
            out.append(ch)
            in_string = not in_string
            continue
        if in_string:
            out.append(ch)
            continue
        if ch in '{[':
            out.append(ch)
            out.append('\n')
            indent += 1
            out.append('  ' * indent)
            continue
        if ch in '}]':
            out.append('\n')
            indent = max(0, indent - 1)
            out.append('  ' * indent)
            out.append(ch)
            continue
        if ch == ',':
            out.append(ch)
            out.append('\n')
            out.append('  ' * indent)
            continue
        if ch == ':':
            out.append(ch)
            out.append(' ')
            continue
        if ch in ['\r', '\n', '\t']:
            continue
        out.append(ch)

    return ''.join(out)


def _aes_cipher(mode):
    cipher = Cipher.getInstance(TRANSFORMATION)
    key_bytes = String(KEY).getBytes("UTF-8")
    skey = SecretKeySpec(key_bytes, "AES")
    cipher.init(mode, skey)
    return cipher


def encrypt_text(plaintext):
    if plaintext is None:
        return None
    cipher = _aes_cipher(Cipher.ENCRYPT_MODE)
    data = String(plaintext).getBytes("UTF-8")
    out = cipher.doFinal(data)
    return Base64.getEncoder().encodeToString(out)


def decrypt_text(ciphertext_b64):
    if ciphertext_b64 is None:
        return None
    cleaned = _clean_b64(ciphertext_b64)
    if cleaned is None or cleaned == "":
        return None
    cipher = _aes_cipher(Cipher.DECRYPT_MODE)
    raw = Base64.getDecoder().decode(cleaned)
    out = cipher.doFinal(raw)
    return String(out, "UTF-8")


# ---------------------------------------------------------------------------
# Simple SnapDramas JSON parsing
# ---------------------------------------------------------------------------

def _extract_data_field(body):
    """Extract the value of top-level JSON field data from {\"data\":\"...\"}."""
    if body is None:
        return None
    text = _to_text(body)
    if text is None:
        return None
    t = text.strip()
    if not t.startswith('{'):
        return None
    if '"data"' not in t:
        return None

    m = re.search(r'"data"\s*:\s*"((?:\\.|[^"\\])*)"', t, re.S)
    if not m:
        return None
    return _json_unescape(m.group(1))


def _build_data_body(ciphertext_b64):
    return '{"%s":"%s"}' % (DATA_FIELD, _json_escape(ciphertext_b64))


# ---------------------------------------------------------------------------
# Burp message helpers
# ---------------------------------------------------------------------------

def _message_info(helpers, content, is_request):
    if is_request:
        return helpers.analyzeRequest(content)
    return helpers.analyzeResponse(content)


def _get_body(helpers, content, is_request):
    info = _message_info(helpers, content, is_request)
    offset = info.getBodyOffset()
    body = helpers.bytesToString(content[offset:])
    return info, offset, body


def _rebuild_message(helpers, original_message, new_body, is_request):
    info = _message_info(helpers, original_message, is_request)
    headers = []
    for h in info.getHeaders():
        if h.lower().startswith('content-length:'):
            continue
        headers.append(h)
    return helpers.buildHttpMessage(headers, helpers.stringToBytes(new_body))


def _looks_like_snap_payload(body):
    if body is None:
        return False
    t = _to_text(body)
    if t is None:
        return False
    t = t.strip()
    return t.startswith('{') and '"data"' in t


# ---------------------------------------------------------------------------
# Tab editor
# ---------------------------------------------------------------------------

class SnapTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.helpers = extender.helpers
        self.controller = controller
        self.editable = editable
        self.current_message = None
        self.current_plain = None
        self.current_cipher = None
        self.current_is_request = False
        self.enabled_for_message = False

        self.text = JTextArea()
        self.text.setLineWrap(True)
        self.text.setWrapStyleWord(True)
        self.text.setEditable(editable)
        self.component = JScrollPane(self.text)
        self.component.setPreferredSize(Dimension(1000, 650))

    def getTabCaption(self):
        return TAB_NAME

    def getUiComponent(self):
        return self.component

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            _, _, body = _get_body(self.helpers, content, isRequest)
            if body is None:
                return False
            t = body.strip()
            if not t:
                return False
            if _looks_like_snap_payload(t):
                return True
            # Allow raw base64 bodies too.
            if _clean_b64(t):
                return True
            return False
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self.current_message = content
        self.current_is_request = isRequest
        self.current_plain = None
        self.current_cipher = None
        self.enabled_for_message = False
        self.text.setText("")

        if content is None:
            return

        try:
            _, _, body = _get_body(self.helpers, content, isRequest)
            if body is None:
                return

            raw = body.strip()
            if not raw:
                return

            cipher_text = None
            if _looks_like_snap_payload(raw):
                cipher_text = _extract_data_field(raw)
            else:
                cipher_text = raw

            if cipher_text is None:
                self.text.setText(raw)
                return

            plain = decrypt_text(cipher_text)
            if plain is None:
                self.text.setText(raw)
                return

            self.enabled_for_message = True
            self.current_cipher = cipher_text
            self.current_plain = plain
            self.text.setText(_pretty_json(plain))
            self.text.setCaretPosition(0)
        except Exception as e:
            self.text.setText('[decrypt error] %s' % str(e))

    def getMessage(self):
        if not self.editable or not self.enabled_for_message:
            return self.current_message

        try:
            edited_plain = self.text.getText()
            if edited_plain is None:
                return self.current_message

            edited_plain = String(edited_plain).toString().strip()
            if edited_plain == "":
                return self.current_message

            new_cipher = encrypt_text(edited_plain)
            if new_cipher is None:
                return self.current_message

            new_body = _build_data_body(new_cipher)
            return _rebuild_message(self.helpers, self.current_message, new_body, self.current_is_request)
        except Exception:
            return self.current_message

    def isModified(self):
        if not self.editable:
            return False
        try:
            current = self.text.getText()
            if current is None:
                return False
            current = current.strip()
            if self.current_plain is None:
                return len(current) > 0
            return current != _pretty_json(self.current_plain).strip()
        except Exception:
            return False

    def getSelectedData(self):
        return self.text.getSelectedText()


# ---------------------------------------------------------------------------
# Extension UI
# ---------------------------------------------------------------------------

class SnapDramasBurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName('SnapDramas AES')
        callbacks.registerMessageEditorTabFactory(self)

        self.panel = self._build_panel()
        callbacks.addSuiteTab(self)
        self._log('SnapDramas AES loaded')
        self._log('Transformation: %s' % TRANSFORMATION)
        self._log('Key loaded')

    def createNewInstance(self, controller, editable):
        return SnapTab(self, controller, editable)

    def getTabCaption(self):
        return TAB_NAME

    def getUiComponent(self):
        return self.panel

    def _build_panel(self):
        panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel('SnapDramas AES Extension'))
        panel.add(top, BorderLayout.NORTH)

        self.log_area = JTextArea(18, 100)
        self.log_area.setEditable(False)
        self.log_area.setLineWrap(True)
        self.log_area.setWrapStyleWord(True)
        panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        bottom = JPanel(FlowLayout(FlowLayout.LEFT))
        self.chk = JCheckBox('Enabled', True)
        self.chk.addActionListener(self._toggle_enabled)
        bottom.add(self.chk)

        btn_key = JButton('Show Key')
        btn_key.addActionListener(self._show_key)
        bottom.add(btn_key)

        btn_clear = JButton('Clear Log')
        btn_clear.addActionListener(self._clear_log)
        bottom.add(btn_clear)

        panel.add(bottom, BorderLayout.SOUTH)
        return panel

    def _toggle_enabled(self, event):
        self._log('Enabled = %s' % str(self.chk.isSelected()))

    def _show_key(self, event):
        self._log('AES key: %s' % KEY)
        self._log('Algorithm: %s' % TRANSFORMATION)

    def _clear_log(self, event):
        try:
            self.log_area.setText('')
        except Exception:
            pass

    def _log(self, msg):
        try:
            self.log_area.append(str(msg) + '\n')
            self.stdout.println(str(msg))
        except Exception:
            pass


BurpExtender = SnapDramasBurpExtender
