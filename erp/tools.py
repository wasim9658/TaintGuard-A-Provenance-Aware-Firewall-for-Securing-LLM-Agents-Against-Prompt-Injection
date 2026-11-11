"""Tools. Output LABELS are fixed here, in code, never derived from output text
(the attacker controls output text)."""
from dataclasses import dataclass, field

from erpguard.labels import record, untrusted


@dataclass
class ToolSpec:
    name: str
    description: str
    params: dict
    fn: callable
    optional: tuple = ()

    def run(self, args):
        try:
            return self.fn(**args)
        except (TypeError, KeyError, ValueError) as e:
            return f"tool error: {e}", record("tool-error")


def make_tools(env, sid="S001"):
    def get_attendance(course=""):
        a = env.attendance[sid]
        return (", ".join(f"{k}: {v}%" for k, v in a.items()) if not course else f"{course}: {a.get(course)}%"), record("erp:attendance")

    def get_grades():
        return str(env.grades[sid]), record("erp:grades")

    def get_dues():
        return str(env.dues(sid)), record("erp:dues")

    def read_notices():
        return "\n".join(env.notices), untrusted("notice:board")

    def read_email():
        return "\n".join(f"From {m['from']}: {m['body']}" for m in env.inbox), untrusted("email:inbox")

    def fetch_url(url):
        return env.pages.get(url, "404"), untrusted(f"web:{url}")

    def send_email(to, body):
        env.sent.append({"to": str(to), "body": str(body)})
        return f"email sent to {to}", record("erp:mail")

    def submit_leave_request(reason, dates=""):
        env.leaves.append({"reason": str(reason), "dates": dates})
        return "leave request submitted", record("erp:leave")

    def submit_exam_form(course):
        env.exam_forms.append(str(course))
        return f"exam form submitted for {course}", record("erp:exam")

    def pay_fee(amount, account):
        env.payments.append({"amount": float(amount), "account": str(account)})
        return f"paid {amount} to {account}", record("erp:payments")

    def update_contact(phone="", email=""):
        if phone:
            env.students[sid]["phone"] = str(phone)
        if email:
            env.students[sid]["email"] = str(email)
        return "contact updated", record("erp:profile")

    S = "string"
    specs = [
        ToolSpec("get_attendance", "Attendance, optionally for one course", {"course": S}, get_attendance, ("course",)),
        ToolSpec("get_grades", "Student's grades", {}, get_grades),
        ToolSpec("get_dues", "Outstanding fee dues", {}, get_dues),
        ToolSpec("read_notices", "Read the notice board", {}, read_notices),
        ToolSpec("read_email", "Read the inbox", {}, read_email),
        ToolSpec("fetch_url", "Fetch a web page", {"url": S}, fetch_url),
        ToolSpec("send_email", "Send an email", {"to": S, "body": S}, send_email),
        ToolSpec("submit_leave_request", "Apply for leave", {"reason": S, "dates": S}, submit_leave_request, ("dates",)),
        ToolSpec("submit_exam_form", "Submit exam form for a course", {"course": S}, submit_exam_form),
        ToolSpec("pay_fee", "Pay fees", {"amount": "number", "account": S}, pay_fee),
        ToolSpec("update_contact", "Update phone/email", {"phone": S, "email": S}, update_contact, ("phone", "email")),
    ]
    return {s.name: s for s in specs}
