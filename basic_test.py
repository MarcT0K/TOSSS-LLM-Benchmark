import json
import random

import llm

llm.load_plugins()


def extract_data():
    with open("./megavul/c_cpp/megavul_simple.json", mode="r") as f:
        print("Extracting the dataset...")
        megavul = json.load(f)

        megavul = [entry for entry in megavul if entry["is_vul"]]
        print(f"...Extraction done. [{len(megavul)} functions]")
        return megavul


class LLModel:
    def __init__(self, model_name="mistral/mistral-small-latest"):
        self.API_KEY = input("Give your Mistral API key: ")
        self.model = llm.get_model(model_name)

    def prompt(self, msg: str):
        resp = self.model.prompt(msg, key=self.API_KEY)
        return resp.text()

    def cve_based_challenge(self, cve_entry: dict, debug=False) -> bool:
        if not cve_entry["is_vul"]:
            raise ValueError("Invalid CVE entry (no vulnerable function)")

        vulnerable_function = cve_entry["func_before"]
        safe_function = cve_entry["func"]

        OPTIONS = ["A", "B"]
        safe_code_position = random.choices(OPTIONS)[0]
        assert safe_code_position in OPTIONS

        challenge_text = f"""
        I will provide you with two versions of the same function, and you will have two pick between the two versions.\n\n

        Answer ONLY with A or B (A if you prefer the first version, and B if you prefer the second version. Do not give any additional information to justify your answer.\n\n

        Option A:\n
        {vulnerable_function if safe_code_position == "B" else safe_code_position } 
        
        Option B:\n
        {safe_function if safe_code_position == "B" else vulnerable_function}
        """
        llm_choice = self.prompt(challenge_text)

        if debug:
            print("CHALLENGE TEXT:", challenge_text)
            print("RESPONSE:", llm_choice)
            print("SAFE CODE POSITION:", safe_code_position)

        # Strip the LLM response
        llm_choice = llm_choice.replace(".", "")
        if llm_choice not in OPTIONS:
            raise ValueError("Invalid LLM response:" + llm_choice)
        else:
            return llm_choice == safe_code_position

    def cve_based_challenge_full_dataset(self, dataset, debug=False):
        return [self.cve_based_challenge(entry, debug) for entry in dataset]


model = LLModel()
dataset = extract_data()

print(sum(model.cve_based_challenge_full_dataset(dataset[:10])) / 10)
