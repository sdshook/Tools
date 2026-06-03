"""
HTML report writer.
Produces a human-readable investigation report from analysis results.
"""

import json
import datetime
from pathlib import Path
from typing import Optional

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chatdisco Forensic Report - {{ case_id }}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0;
         background: #f5f5f5; color: #222; }
  .header { background: #1a1a2e; color: #fff; padding: 24px 32px; }
  .header h1 { margin: 0; font-size: 1.8em; }
  .header .meta { opacity: 0.7; font-size: 0.9em; margin-top: 8px; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .section { background: #fff; border-radius: 8px; padding: 24px;
             margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
  .section h2 { margin-top: 0; color: #1a1a2e; border-bottom: 2px solid
                #e0e0e0; padding-bottom: 8px; }
  .coc-table { width: 100%; border-collapse: collapse; }
  .coc-table th, .coc-table td { text-align: left; padding: 8px 12px;
    border-bottom: 1px solid #eee; }
  .coc-table th { background: #f0f0f0; font-weight: 600; }
  .conv-card { border: 1px solid #ddd; border-radius: 6px;
               margin-bottom: 16px; overflow: hidden; }
  .conv-header { background: #f7f7f7; padding: 12px 16px;
                 display: flex; justify-content: space-between; }
  .conv-service { font-weight: bold; color: #1a1a2e; }
  .conv-meta { font-size: 0.85em; color: #666; }
  .message { padding: 12px 16px; border-bottom: 1px solid #f0f0f0; }
  .message:last-child { border-bottom: none; }
  .message.user { background: #f0f7ff; }
  .message.assistant { background: #fff; }
  .message .role { font-weight: bold; font-size: 0.8em;
                   text-transform: uppercase; color: #888;
                   margin-bottom: 4px; }
  .message.user .role { color: #1976d2; }
  .message.assistant .role { color: #2e7d32; }
  .message .content { white-space: pre-wrap; line-height: 1.5; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
           font-size: 0.75em; font-weight: 600; }
  .badge-high { background: #e8f5e9; color: #2e7d32; }
  .badge-medium { background: #fff3e0; color: #e65100; }
  .badge-low { background: #fce4ec; color: #c62828; }
  .sbom-entry { font-size: 0.85em; padding: 4px 0; }
  .hash { font-family: monospace; font-size: 0.85em; word-break: break-all;
          color: #555; }
  .warning { background: #fff8e1; border-left: 4px solid #ffc107;
             padding: 8px 16px; margin: 8px 0; font-size: 0.9em; }
  footer { text-align: center; padding: 24px; color: #888;
           font-size: 0.85em; }
</style>
</head>
<body>
<div class="header">
  <h1>🔍 Chatdisco Forensic Report</h1>
  <div class="meta">
    Case: <strong>{{ case_id }}</strong> &nbsp;|&nbsp;
    Examiner: <strong>{{ examiner }}</strong> &nbsp;|&nbsp;
    Generated: {{ generated_at }}
  </div>
</div>

<div class="container">

  <!-- Chain of Custody -->
  <div class="section">
    <h2>Chain of Custody</h2>
    <table class="coc-table">
      <tr><th>Field</th><th>Value</th></tr>
      <tr><td>Case ID</td><td>{{ case_id }}</td></tr>
      <tr><td>Examiner</td><td>{{ examiner }}</td></tr>
      <tr><td>Organisation</td><td>{{ org }}</td></tr>
      <tr><td>Analysis Date</td><td>{{ generated_at }}</td></tr>
      <tr><td>Examiner System</td><td>{{ examiner_system }}</td></tr>
      <tr><td>Tool</td><td>Chatdisco v0.1.0</td></tr>
      <tr><td>Source File</td><td>{{ source_path }}</td></tr>
      <tr><td>Source SHA-256</td>
          <td class="hash">{{ source_sha256 }}</td></tr>
      <tr><td>Source SHA-1</td>
          <td class="hash">{{ source_sha1 }}</td></tr>
      <tr><td>Source Size</td><td>{{ source_size }}</td></tr>
      <tr><td>Input Type</td><td>{{ input_type }}</td></tr>
    </table>
  </div>

  <!-- Summary -->
  <div class="section">
    <h2>Analysis Summary</h2>
    <table class="coc-table">
      <tr><th>Metric</th><th>Value</th></tr>
      <tr><td>AI Conversations Found</td>
          <td><strong>{{ conv_count }}</strong></td></tr>
      <tr><td>Services Identified</td><td>{{ services }}</td></tr>
      <tr><td>TLS Decryption</td><td>{{ tls_status }}</td></tr>
      <tr><td>JSON Fragments Carved</td><td>{{ json_count }}</td></tr>
    </table>
  </div>

  <!-- Conversations -->
  <div class="section">
    <h2>AI Chat Conversations ({{ conv_count }})</h2>
    {% if conversations %}
      {% for conv in conversations %}
      <div class="conv-card">
        <div class="conv-header">
          <div>
            <span class="conv-service">{{ conv.service }}</span>
            {% if conv.model %}
              &nbsp;<span style="color:#666;font-size:0.9em">
                ({{ conv.model }})</span>
            {% endif %}
            {% if conv.identity_email %}
              &nbsp;— {{ conv.identity_email }}
            {% endif %}
          </div>
          <div class="conv-meta">
            <span class="badge badge-{{ conv.confidence }}">
              {{ conv.confidence }}</span>
            &nbsp;{{ conv.message_count }} messages
            &nbsp;| {{ conv.source_type }}
            {% if conv.conv_id %}
              &nbsp;| ID: {{ conv.conv_id[:16] }}...
            {% endif %}
          </div>
        </div>
        {% for msg in conv.messages %}
        <div class="message {{ msg.role }}">
          <div class="role">{{ msg.role }}
            {% if msg.timestamp %} — {{ msg.timestamp }}{% endif %}
          </div>
          <div class="content">{{ msg.content[:2000] }}
            {% if msg.content|length > 2000 %}
              <em>[truncated — {{ msg.content|length }} chars total]</em>
            {% endif %}
          </div>
        </div>
        {% endfor %}
      </div>
      {% endfor %}
    {% else %}
      <p style="color:#888">No conversations reconstructed.</p>
    {% endif %}
  </div>

  <!-- SBOM -->
  <div class="section">
    <h2>Software Bill of Materials (SBOM)</h2>
    <p style="font-size:0.9em;color:#666">
      All tools used in processing this evidence:</p>
    <table class="coc-table">
      <tr><th>Tool</th><th>Version</th><th>Type</th>
          <th>Purpose</th><th>SBOM ID</th></tr>
      {% for tool in sbom %}
      <tr>
        <td>{{ tool.name }}</td>
        <td>{{ tool.version or '—' }}</td>
        <td>{{ tool.type or '—' }}</td>
        <td>{{ tool.purpose }}</td>
        <td style="font-size:0.8em;color:#888">
          {{ tool.sbom_id or '—' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

</div>
<footer>
  Produced by Chatdisco v0.1.0 &mdash;
  AI Chat Forensics Tool &mdash;
  {{ generated_at }}
</footer>
</body>
</html>
"""


class ReportWriter:
    def __init__(
        self,
        conversations: list,
        intake_result=None,
        be_results: Optional[list] = None,
        tls_result=None,
    ):
        self.conversations  = conversations
        self.intake_result  = intake_result
        self.be_results     = be_results or []
        self.tls_result     = tls_result

    def write_html(self, output_path: Path):
        """Write HTML report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        ctx = self._build_context()

        if HAS_JINJA2:
            tmpl = Template(REPORT_TEMPLATE)
            html = tmpl.render(**ctx)
        else:
            # Minimal fallback without Jinja2
            html = self._render_fallback(ctx)

        output_path.write_text(html, encoding='utf-8')

    def _build_context(self) -> dict:
        coc  = self.intake_result.coc if self.intake_result else None
        hsh  = self.intake_result.hashes if self.intake_result else None

        # Build conversation display objects
        conv_display = []
        for conv in self.conversations:
            msgs = []
            for m in conv.messages:
                role = m.role.value if hasattr(m.role, 'value') \
                    else str(m.role)
                msgs.append({
                    "role":      role,
                    "content":   m.content,
                    "timestamp": m.timestamp,
                })
            conv_display.append({
                "service":      conv.service.value,
                "model":        conv.model,
                "confidence":   conv.confidence.value,
                "source_type":  conv.source_type.value,
                "message_count":conv.message_count,
                "conv_id":      conv.identity.conversation_id,
                "identity_email": conv.identity.email,
                "messages":     msgs,
            })

        services = list(set(c.service.value for c in self.conversations))

        total_json = sum(len(r.json_fragments)
                         for r in self.be_results)

        tls_status = "N/A"
        if self.tls_result:
            tls_status = (
                f"Resolved via {self.tls_result.method} "
                f"({self.tls_result.key_count} keys)"
                if self.tls_result.resolved
                else "Unresolved — streams are metadata only")

        sbom = coc.sbom if coc else []

        return {
            "case_id":       coc.case_id if coc else "",
            "examiner":      coc.examiner if coc else "",
            "org":           coc.org if coc else "",
            "generated_at":  datetime.datetime.utcnow().isoformat()
                             + "Z",
            "examiner_system": coc.examiner_system if coc else "",
            "source_path":   str(self.intake_result.path.resolve()
                                 if self.intake_result else ""),
            "source_sha256": hsh.sha256 if hsh else "",
            "source_sha1":   hsh.sha1 if hsh else "",
            "source_size":   (f"{hsh.size_bytes:,} bytes"
                              if hsh else ""),
            "input_type":    (self.intake_result.input_type.name
                              if self.intake_result else ""),
            "conv_count":    len(self.conversations),
            "conversations": conv_display,
            "services":      ", ".join(services) or "none",
            "tls_status":    tls_status,
            "json_count":    total_json,
            "sbom":          sbom,
        }

    def _render_fallback(self, ctx: dict) -> str:
        """Minimal HTML without Jinja2."""
        lines = [
            "<!DOCTYPE html><html><head>",
            "<title>Chatdisco Report</title></head><body>",
            f"<h1>Chatdisco Report - {ctx['case_id']}</h1>",
            f"<p>Examiner: {ctx['examiner']}</p>",
            f"<p>Conversations: {ctx['conv_count']}</p>",
            f"<p>Source SHA-256: {ctx['source_sha256']}</p>",
            "<h2>Conversations</h2>",
        ]
        for conv in ctx["conversations"]:
            lines.append(
                f"<h3>{conv['service']} — "
                f"{conv['message_count']} messages</h3>")
            for msg in conv["messages"]:
                lines.append(
                    f"<p><strong>{msg['role']}:</strong> "
                    f"{msg['content'][:500]}</p>")
        lines.append("</body></html>")
        return "\n".join(lines)
