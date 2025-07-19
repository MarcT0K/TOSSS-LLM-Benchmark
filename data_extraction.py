import json

with open("./megavul/c_cpp/megavul_simple.json", mode="r") as f:
    megavul = json.load(f)
    item = megavul[9]
    cve_id = item["cve_id"]  # CVE-2022-24786
    cvss_vector = item["cvss_vector"]  # AV:N/AC:L/Au:N/C:P/I:P/A:P
    is_vul = item["is_vul"]  # True
    if is_vul:
        func_before = item["func_before"]  # vulnerable function
        print("FUNCTION BEFORE:", func_before)

    func_after = item["func"]  # after vul function fixed(i.e., clean function)
    print("FUNCTION AFTER:", func_after)
