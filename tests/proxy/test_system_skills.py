from airecon.proxy.system import auto_load_skills_for_message


def test_auto_load_reversing_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "need reverse engineering with radare2 and objdump for this ELF"
    )
    assert "ctf/reversing.md" in ctx
    assert "reversing" in loaded


def test_auto_load_pwn_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "help me build pwntools rop ret2libc exploit for pwn challenge"
    )
    assert "ctf/pwn.md" in ctx
    assert "pwn" in loaded


def test_auto_load_osint_skill_keywords():
    ctx, loaded = auto_load_skills_for_message(
        "run osint with asn and whois plus certificate transparency data"
    )
    assert "reconnaissance/asn_whois_osint.md" in ctx
    assert "asn_whois_osint" in loaded
