# SnapDramas Burp Extension
# Legacy Jython extension for Burp Suite
# Decrypts/encrypts SnapDramas traffic using AES/ECB/PKCS5Padding + Base64

from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec
from java.util import Base64
from java.lang import String
from java.awt import BorderLayout, FlowLayout
from javax.swing import JPanel, JLabel, JScrollPane, JTextArea, JButton
from org.json import JSONObject

KEY = "ipB7OHxAmJ9Qa1Lf38X1bP71zJMe4Yw6"
TRANSFORMATION = "AES/ECB/PKCS5Padding"
TAB_NAME = "SnapDramas AES"


def aes_cipher(mode):
    cipher = Cipher.getInstance(TRANSFORMATION)
    key_bytes = String(KEY).getBytes("UTF-8")
    key = SecretKeySpec(key_bytes, "AES")
    cipher.init(mode, key)
    return cipher


def encrypt_text(plaintext):
    if plaintext is None:
        return None
    cipher = aes_cipher(Cipher.ENCRYPT_MODE)
    data = String(plaintext).getBytes("UTF-8")
    enc = cipher.doFinal(data)
    return Base64.getEncoder().encodeToString(enc)


def decrypt_text(ciphertext_b64):
    if ciphertext_b64 is None:
        return None
    cleaned = String(ciphertext_b64).replaceAll("[^A-Za-z0-9+/=]", "").trim()
    cipher = aes_cipher(Cipher.DECRYPT_MODE)
    raw = Base64.getDecoder().decode(cleaned)
    out = cipher.doFinal(raw)
    return String(out, "UTF-8")


def pretty_json(text):
    try:
        return JSONObject(text).toString(2)
    except Exception:
        return text


def try_extract_data_field(body):
    if body is None:
        return None
    body = body.strip()
    if not body:
        return None

    # Most common case: {"data":"..."}
    if body.startswith('{') and '"data"' in body:
        try:
            obj = JSONObject(body)
            return obj.getString("data")
        except Exception:
            pass

    # Plain string body or unexpected JSON-like wrapper
    return body


def build_json_data_body(ciphertext_b64):
    obj = JSONObject()
    obj.put("data", ciphertext_b64)
    return obj.toString()


class SnapTab(object, IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.helpers = extender.helpers
        self.controller = controller
        self.editable = editable
        self.current_message = None
        self.current_plain = None
        self.is_request = False
        self.compatible = False
        self.text = JTextArea()
        self.text.setLineWrap(True)
        self.text.setWrapStyleWord(True)
        self.text.setEditable(editable)
        self.component = JScrollPane(self.text)

    def getTabCaption(self):
        return TAB_NAME

    def getUiComponent(self):
        return self.component

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            info = self.helpers.analyzeRequest(content) if isRequest else self.helpers.analyzeResponse(content)
            body = self.helpers.bytesToString(content[info.getBodyOffset():])
            if body is None:
                return False
            body = body.strip()
            return body.startswith('{') and 'data' in body
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self.current_message = content
        self.is_request = isRequest
        self.compatible = False
        self.current_plain = None
        self.text.setText("")

        if content is None:
            return

        try:
            info = self.helpers.analyzeRequest(content) if isRequest else self.helpers.analyzeResponse(content)
            body = self.helpers.bytesToString(content[info.getBodyOffset():])
            ciphertext = try_extract_data_field(body)
            if ciphertext is None:
                self.text.setText(body)
                return

            plain = decrypt_text(ciphertext)
            self.current_plain = plain
            self.compatible = True
            if plain is None:
                self.text.setText(body)
            else:
                self.text.setText(pretty_json(plain))
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

            edited_plain = String(edited_plain).trim().toString()
            ciphertext = encrypt_text(edited_plain)
            if ciphertext is None:
                return self.current_message

            new_body = build_json_data_body(ciphertext)
            msg = self.current_message
            info = self.helpers.analyzeRequest(msg) if self.is_request else self.helpers.analyzeResponse(msg)
            headers = list(info.getHeaders())
            body_bytes = self.helpers.stringToBytes(new_body)
            return self.helpers.buildHttpMessage(headers, body_bytes)
        except Exception:
            return self.current_message

    def isModified(self):
        if not self.editable:
            return False
        try:
            current = self.text.getText()
            if self.current_plain is None:
                return current is not None and len(current) > 0
            return String(current).toString() != String(pretty_json(self.current_plain)).toString()
        except Exception:
            return False

    def getSelectedData(self):
        return self.text.getSelectedText()


class SnapDramasBurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SnapDramas AES")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.addSuiteTab(self)
        self.panel = self._build_panel()
        self._log("Loaded. Key = %s" % KEY)
        self._log("Transformation = %s" % TRANSFORMATION)

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

        self.log_area = JTextArea(18, 100)
        self.log_area.setEditable(False)
        self.log_area.setLineWrap(True)
        self.log_area.setWrapStyleWord(True)
        panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        bottom = JPanel(FlowLayout(FlowLayout.LEFT))
        btn = JButton("Show Config")
        btn.addActionListener(self._show_config)
        bottom.add(btn)
        panel.add(bottom, BorderLayout.SOUTH)
        return panel

    def _show_config(self, event):
        self._log("AES key: %s" % KEY)
        self._log("Algorithm: %s" % TRANSFORMATION)
        self._log("Request/Response bodies are expected to contain JSON field 'data'.")

    def _log(self, text):
        try:
            self.log_area.append(text + "\n")
        except Exception:
            pass


BurpExtender = SnapDramasBurpExtender
