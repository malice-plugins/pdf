REPO=malice-plugins/pdf
ORG=malice
NAME=pdf
CATEGORY=doc
VERSION=$(shell cat VERSION)
MALWARE="test/eicar.pdf"


all: build size test test-markdown

build: ## Build docker image
	docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size: build ## Get built image size
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: tar
tar: build
	@docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

.PHONY: malware
malware:
	cd test; wget https://didierstevens.com/files/data/pdf-doc-vba-eicar-dropper.zip
	cd test; unzip -P EICARdropper pdf-doc-vba-eicar-dropper.zip
	cd test; mv pdf-doc-vba-eicar-dropper.pdf eicar.pdf
	cd test; rm pdf-doc-vba-eicar-dropper.zip
	cd test; echo "TEST" > not.pdf

.PHONY: test
test:
	@echo "===> Starting elasticsearch"
	@docker rm -f elasticsearch || true
	@docker run --init -d --name elasticsearch -p 9200:9200 blacktop/elasticsearch:5.5
	@echo "===> ${NAME} --help"
	@docker run --rm $(ORG)/$(NAME):$(VERSION); sleep 10
	@echo "===> ${NAME} malware test"
	@docker run --rm --link elasticsearch -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) scan --elasticsearch elasticsearch -vvvv $(MALWARE) | jq . > docs/results.json
	@cat docs/results.json | jq .

.PHONY: test-markdown
test-markdown:
	@echo "===> ${NAME} pull MarkDown from elasticsearch results"
	@http localhost:9200/malice/_search | jq . > docs/elastic.json
	@cat docs/elastic.json | jq '.hits.hits[] ._source.plugins.${CATEGORY}' | jq -r '.["${NAME}"].markdown' > docs/SAMPLE.md
	@docker rm -f elasticsearch

.PHONY: test_web
test_web:
	@echo "===> Starting web service"
	@docker run --rm -p 3993:3993 $(ORG)/$(NAME):$(VERSION) web
	# http -f localhost:3993/scan malware@test/eicar.pdf

.PHONY: run
run: stop ## Run docker container
	@docker run --init -d --name $(NAME) -p 9200:9200 $(ORG)/$(NAME):$(VERSION)

.PHONY: ssh
ssh: ## SSH into docker image
	@echo "===> Starting elasticsearch"
	@docker rm -f elasticsearch || true
	@docker run --init -d --name elasticsearch -p 9200:9200 blacktop/elasticsearch
	@docker run -it --rm --link elasticsearch -v $(PWD):/malware --entrypoint=sh $(ORG)/$(NAME):$(VERSION)

.PHONY: stop
stop: ## Kill running docker containers
	@docker rm -f $(NAME) || true

circle: ci-size
	@sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/SIZE)-blue/' README.md
	@echo "===> Image size is: $(shell cat .circleci/SIZE)"

ci-build:
	@echo "===> Getting CircleCI build number"
	@http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num

ci-size: ci-build
	@echo "===> Getting image build size from CircleCI"
	@http "$(shell http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq '.[].url')" > .circleci/SIZE

clean: clean_pyc ## Clean docker image and stop all running containers
	docker-clean stop
	docker rmi $(ORG)/$(NAME):$(VERSION) || true
	docker rmi $(ORG)/$(NAME):dev || true
	rm $(MALWARE) || true
	rm README.md.bu || true

.PHONY: clean_pyc
clean_pyc:  ## Clean all compiled python files
	find . -name "*.pyc" -exec rm -f {} \;

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
