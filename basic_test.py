import llm

MISTRAL_API_KEY = input("Give your Mistral API key")

llm.load_plugins()

model = llm.get_model("mistral/mistral-small-latest")

response = model.prompt("Tell me something original", key=MISTRAL_API_KEY )
print(response.text())