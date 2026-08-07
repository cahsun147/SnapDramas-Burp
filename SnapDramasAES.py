# SnapDramas Burp Extension
#
# Jython Burp extension for SnapDramas traffic.
# Features:
# - AES/ECB/PKCS5Padding decrypt/encrypt
# - Base64 transport
# - Burp message editor tab for viewing/editing plaintext JSON
# - Request/response support
#
# Notes:
# - Compatible with Jython 2.7 in Burp.
# - Does not depend on org.json.
# - If a message is not recognized as SnapDramas encrypted payload, the tab stays disabled.

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec
from java.util import Base64
from java.lang import String
from java.awt import BorderLayout, FlowLayout
from javax.swing import JPanel, JLabel, JScrollPane, JTextArea, JButton, JCheckBox, JSeparator
from javax.swing import JOptionPane
from java.awt import Dimension
from java.awt.event import ActionListener
from java.io import PrintWriter
from java.lang import Exception as JavaException
import re


KEY = "ipB7OHxAmJ9Qa1Lf38X1bP71zJMe4Yw6"
TRANSFORMATION = "AES/ECB/PKCS5Padding"
TAB_NAME = "SnapDramas AES"
JSON_FIELD = "data"


# ---------------------------------------------------------------------------
# Small utility helpers
# ---------------------------------------------------------------------------

def _to_str(value):
    if value is None:
        return None
    try:
        return String(value).toString()
    except Exception:
        try:
            return str(value)
        except Exception:
            return None


def _strip_non_base64(value):
    if value is None:
        return None
    text = _to_str(value)
    if text is None:
        return None
    return re.sub(r"[^A-Za-z0-9+/=]", "", text).strip()


def _looks_like_json(text):
    if text is None:
        return False
    t = text.strip()
    return (t.startswith('{') and t.endswith('}')) or (t.startswith('[') and t.endswith(']'))


def _unescape_json_string(s):
    # Minimal JSON-string unescape for content inside double quotes.
    # Enough for common payloads used by this extension.
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


def _escape_json_string(s):
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


def _pretty_json_minimal(text):
    """Pretty-print by preserving the body as text if JSON parsing is unavailable.

    We deliberately avoid org.json / Python json to remain compatible with Burp's
    Jython runtime. This function normalizes whitespace lightly and leaves the
    content readable without full parsing.
    """
    if text is None:
        return None
    t = _to_str(text)
    if t is None:
        return None
    if not _looks_like_json(t):
        return t

    # A lightweight formatter that inserts indentation around common JSON syntax.
    # It is intentionally conservative.
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
    pretty = ''.join(out)
    return pretty


# ---------------------------------------------------------------------------
# AES helpers
# ---------------------------------------------------------------------------

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
    cleaned = _strip_non_base64(ciphertext_b64)
    if cleaned is None or cleaned == "":
        return None
    cipher = _aes_cipher(Cipher.DECRYPT_MODE)
    raw = Base64.getDecoder().decode(cleaned)
    out = cipher.doFinal(raw)
    return String(out, "UTF-8")


# ---------------------------------------------------------------------------
# JSON body helpers (no org.json)
# ---------------------------------------------------------------------------

def _find_data_field(body):
    """Extract the value of top-level JSON field "data".

    Supports only the common SnapDramas payload structure:
      {"data":"..."}
    If the body is not a matching JSON object, returns None.
    """
    if body is None:
        return None
    text = _to_str(body)
    if text is None:
        return None
    t = text.strip()
    if not t.startswith('{') or '"data"' not in t:
        return None

    # Simple robust scan for top-level "data":"..."
    # We avoid full JSON parsing to remain Jython-compatible.
    key_pat = '"%s"' % JSON_FIELD
    idx = t.find(key_pat)
    if idx < 0:
        return None

    # Find the colon after the key
    colon = t.find(':', idx + len(key_pat))
    if colon < 0:
        return None

    # Skip whitespace
    i = colon + 1
    while i < len(t) and t[i] in ' \r\n\t':
        i += 1
    if i >= len(t):
        return None

    # Expect string value
    if t[i] != '"':
        # For non-string values, capture a simple token until comma/closing brace.
        j = i
        while j < len(t) and t[j] not in ',}':
            j += 1
        val = t[i:j].strip()
        return _unescape_json_string(val)

    # Parse quoted string with escaping
    j = i + 1
    escape = False
    buf = []
    while j < len(t):
        ch = t[j]
        if escape:
            buf.append(ch)
            escape = False
        elif ch == '\\':
            buf.append(ch)
            escape = True
        elif ch == '"':
            return _unescape_json_string(''.join(buf))
        else:
            buf.append(ch)
        j += 1
    return None


def _build_data_body(ciphertext_b64):
    return '{"%s":"%s"}' % (JSON_FIELD, _escape_json_string(ciphertext_b64))


# ---------------------------------------------------------------------------
# Message body handling
# ---------------------------------------------------------------------------

def _get_body_from_message(helpers, content, isRequest):
    if content is None:
        return None, None, None
    info = helpers.analyzeRequest(content) if isRequest else helpers.analyzeResponse(content)
    body_offset = info.getBodyOffset()
    body_bytes = content[body_offset:]
    body = helpers.bytesToString(body_bytes)
    return info, body_offset, body


def _rebuild_message(helpers, original_message, new_body, isRequest):
    info = helpers.analyzeRequest(original_message) if isRequest else helpers.analyzeResponse(original_message)
    headers = list(info.getHeaders())

    # Remove stale Content-Length; buildHttpMessage computes it.
    filtered = []
    for h in headers:
        if h.lower().startswith('content-length:'):
            continue
        filtered.append(h)

    body_bytes = helpers.stringToBytes(new_body)
    return helpers.buildHttpMessage(filtered, body_bytes)


# ---------------------------------------------------------------------------
# Burp editor tab
# ---------------------------------------------------------------------------

class SnapTab(object, IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.helpers = extender.helpers
        self.controller = controller
        self.editable = editable
        self.current_message = None
        self.current_plain = None
        self.current_ciphertext = None
        self.is_request = False
        self.compatible = False
        self.modified_once = False

        self.text = JTextArea()
        self.text.setLineWrap(True)
        self.text.setWrapStyleWord(True)
        self.text.setEditable(editable)
        self.text.setTabSize(2)
        self.component = JScrollPane(self.text)
        self.component.setPreferredSize(Dimension(900, 600))

        # Optional small status indicator for debugging.
        self._last_mode = None

    def getTabCaption(self):
        return TAB_NAME

    def getUiComponent(self):
        return self.component

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            info, _, body = _get_body_from_message(self.helpers, content, isRequest)
            if body is None:
                return False
            t = body.strip()
            if not t:
                return False
            # Expected wrapped payload: {"data":"BASE64..."}
            if t.startswith('{') and '"data"' in t:
                return True
            # Also allow plain base64 body for compatibility.
            if len(_strip_non_base64(t) or '') > 0:
                return True
            return False
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self.current_message = content
        self.is_request = isRequest
        self.compatible = False
        self.current_plain = None
        self.current_ciphertext = None
        self.modified_once = False
        self._last_mode = 'request' if isRequest else 'response'
        self.text.setText("")

        if content is None:
            return

        try:
            _, _, body = _get_body_from_message(self.helpers, content, isRequest)
            if body is None:
                self.text.setText("")
                return

            raw = body.strip()
            ciphertext = None
            if raw.startswith('{') and '"data"' in raw:
                ciphertext = _find_data_field(raw)
            else:
                ciphertext = raw

            if ciphertext is None:
                self.text.setText(raw)
                return

            plaintext = decrypt_text(ciphertext)
            if plaintext is None:
                self.text.setText(raw)
                return

            self.compatible = True
            self.current_ciphertext = ciphertext
            self.current_plain = plaintext
            display = _pretty_json_minimal(plaintext)
            self.text.setText(display if display is not None else plaintext)
            self.text.setCaretPosition(0)
        except Exception as e:
            self.text.setText("[decrypt error] %s" % str(e))

    def getMessage(self):
        if not self.editable or not self.compatible:
            return self.current_message

        try:
            edited_plain = self.text.getText()
            if edited_plain is None:
                return self.current_message
            edited_plain = String(edited_plain).toString().strip()
            if edited_plain == "":
                return self.current_message

            ciphertext = encrypt_text(edited_plain)
            if ciphertext is None:
                return self.current_message

            new_body = _build_data_body(ciphertext)
            rebuilt = _rebuild_message(self.helpers, self.current_message, new_body, self.is_request)
            self.modified_once = True
            return rebuilt
        except Exception:
            return self.current_message

    def isModified(self):
        if not self.editable:
            return False
        try:
            current = self.text.getText()
            if current is None:
                return False
            if self.current_plain is None:
                return len(current.strip()) > 0
            return String(current).toString().strip() != String(_pretty_json_minimal(self.current_plain)).toString().strip()
        except Exception:
            return False

    def getSelectedData(self):
        return self.text.getSelectedText()


# ---------------------------------------------------------------------------
# Main Burp extender
# ---------------------------------------------------------------------------

class SnapDramasBurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.enabled = True

        callbacks.setExtensionName("SnapDramas AES")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.addSuiteTab(self)
        self.panel = self._build_panel()

        self._log("Loaded SnapDramas AES extension")
        self._log("Algorithm: %s" % TRANSFORMATION)
        self._log("Key: %s" % KEY)
        self._log("Expected body format: {\"data\":\"...\"}")

    def createNewInstance(self, controller, editable):
        return SnapTab(self, controller, editable)

    def getTabCaption(self):
        return TAB_NAME

    def getUiComponent(self):
        return self.panel

    def _build_panel(self):
        panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel("SnapDramas AES Burp Extension"))
        panel.add(top, BorderLayout.NORTH)

        self.log_area = JTextArea(20, 100)
        self.log_area.setEditable(False)
        self.log_area.setLineWrap(True)
        self.log_area.setWrapStyleWord(True)
        panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        bottom = JPanel(FlowLayout(FlowLayout.LEFT))
        self.chk_enabled = JCheckBox("Enabled", True)
        self.chk_enabled.addActionListener(self._toggle_enabled)
        bottom.add(self.chk_enabled)

        btn_key = JButton("Show Key")
        btn_key.addActionListener(self._show_key)
        bottom.add(btn_key)

        btn_clear = JButton("Clear Log")
        btn_clear.addActionListener(self._clear_log)
        bottom.add(btn_clear)

        btn_test = JButton("Test Encrypt/Decrypt")
        btn_test.addActionListener(self._self_test)
        bottom.add(btn_test)

        panel.add(bottom, BorderLayout.SOUTH)
        return panel

    def _toggle_enabled(self, event):
        try:
            self.enabled = self.chk_enabled.isSelected()
            self._log("Enabled = %s" % str(self.enabled))
        except Exception as e:
            self._log("Toggle error: %s" % str(e))

    def _show_key(self, event):
        self._log("AES key: %s" % KEY)
        self._log("Transformation: %s" % TRANSFORMATION)

    def _clear_log(self, event):
        try:
            self.log_area.setText("")
        except Exception:
            pass

    def _self_test(self, event):
        try:
            sample = '{"pageNum":1,"pageSize":20,"sort":2,"subtitleLang":"id"}'
            enc = encrypt_text(sample)
            dec = decrypt_text(enc)
            self._log("Self-test input : %s" % sample)
            self._log("Self-test enc   : %s" % enc)
            self._log("Self-test dec   : %s" % dec)
        except Exception as e:
            self._log("Self-test error: %s" % str(e))

    def _log(self, text):
        try:
            msg = _to_str(text)
            if msg is None:
                return
            self.log_area.append(msg + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
            self.stdout.println(msg)
        except Exception:
            pass


# Burp convention: the extender class must be called BurpExtender.
BurpExtender = SnapDramasBurpExtender
