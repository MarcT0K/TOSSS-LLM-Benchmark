## Install requirements
sudo apt install python3-pip wget unzip
pip3 install llm llm-mistral


## Download dataset
wget -O megavul.zip https://www.kaggle.com/api/v1/datasets/download/marcdamie/megavul-a-cc-java-vulnerability-dataset?datasetVersionNumber=1
unzip megavul.zip
rm megavul.zip