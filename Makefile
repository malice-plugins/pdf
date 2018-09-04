REPO=malice-plugins/pdf
ORG=malice
NAME=pdf
CATEGORY=document
VERSION=$(shell cat VERSION)

MALWARE=tests/eicar.pdf
EXTRACT=/malware/tests/dump
MALICE_SCANID?=

all: build size tag test_all

.PHONY: build
build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: ssh
ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

.PHONY: tar
tar:
	docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

.PHONY: start_elasticsearch
start_elasticsearch:
ifeq ("$(shell docker inspect -f {{.State.Running}} elasticsearch)", "true")
	@echo "===> elasticsearch already running.  Stopping now..."
	@docker rm -f elasticsearch || true
endif
	@echo "===> Starting elasticsearch"
	@docker run --init -d --name elasticsearch -p 9200:9200 malice/elasticsearch:6.4; sleep 15

.PHONY: malware
malware:
ifeq (,$(wildcard $(MALWARE)))
	cd tests; wget https://didierstevens.com/files/data/pdf-doc-vba-eicar-dropper.zip
	cd tests; unzip -P EICARdropper pdf-doc-vba-eicar-dropper.zip
	cd tests; mv pdf-doc-vba-eicar-dropper.pdf eicar.pdf
	cd tests; rm pdf-doc-vba-eicar-dropper.zip
	cd tests; echo "TEST" > not.pdf
endif

.PHONY: test_all
test_all: test test_elastic test_markdown test_web

.PHONY: test
test: malware
	@echo "===> ${NAME} --help"
	@docker run --rm $(ORG)/$(NAME):$(VERSION); sleep 10
	@echo "===> ${NAME} malware test"
	@docker run --rm -v $(PWD):/malware -e MALICE_TIMEOUT=120 $(ORG)/$(NAME):$(VERSION) scan $(MALWARE) | jq . > docs/results.json
	# @docker run --rm -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) scan -vvvv -d --output $(EXTRACT) $(MALWARE) | jq . > docs/results.json
	@cat docs/results.json | jq .

.PHONY: test_elastic
test_elastic: start_elasticsearch malware
	@echo "===> ${NAME} test_elastic found"
	docker run --rm --link elasticsearch -e MALICE_ELASTICSEARCH_URL=elasticsearch -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) scan -vvvv -d --output $(EXTRACT) $(MALWARE)
	http localhost:9200/malice/_search | jq . > docs/elastic.json

.PHONY: test_extern_elastic
test_extern_elastic: malware
	@echo "===> ${NAME} test_extern_elastic found"
	docker run --rm \
	-e MALICE_ELASTICSEARCH_URL=${MALICE_ELASTICSEARCH_URL} \
	-e MALICE_ELASTICSEARCH_USERNAME=${MALICE_ELASTICSEARCH_USERNAME} \
	-e MALICE_ELASTICSEARCH_PASSWORD=${MALICE_ELASTICSEARCH_PASSWORD} \
	-e MALICE_ELASTICSEARCH_INDEX="test" \
	-v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) scan -vvvv -d --output $(EXTRACT) $(MALWARE)

.PHONY: test_markdown
test_markdown:
	@echo "===> ${NAME} test_markdown"
	# http localhost:9200/malice/_search query:=@docs/query.json | jq . > docs/elastic.json
	cat docs/elastic.json | jq -r '.hits.hits[] ._source.plugins.${CATEGORY}.${NAME}.markdown' > docs/SAMPLE.md

.PHONY: test_web
test_web: malware stop
	@echo "===> Starting web service"
	@docker run -d --name $(NAME) -p 3993:3993 $(ORG)/$(NAME):$(VERSION) web
	sleep 5; http -f localhost:3993/scan malware@$(MALWARE)
	@echo "===> Stopping web service"
	@docker logs $(NAME)
	@docker rm -f $(NAME)

.PHONY: test_malice
test_malice:
	@echo "===> $(ORG)/$(NAME):$(VERSION) testing with running malice elasticsearch DB (update existing sample)"
	@docker run --rm -e MALICE_SCANID=$(MALICE_SCANID) -e MALICE_ELASTICSEARCH_URL=http://elasticsearch:9200 --link malice-elastic:elasticsearch -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) scan -t -vvvv $(MALWARE)

.PHONY: run
run: stop ## Run docker container
	@docker run --init -d --name $(NAME) -p 9200:9200 $(ORG)/$(NAME):$(VERSION)

.PHONY: stop
stop: ## Kill running docker containers
	@docker rm -f $(NAME) || true

.PHONY: circle
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
	docker rmi $(ORG)/$(NAME):latest || true
	rm $(MALWARE) || true
	rm README.md.bu || true

.PHONY: clean_pyc
clean_pyc:  ## Clean all compiled python files
	find . -name "*.pyc" -exec rm -f {} \;
	rm *.log || true
	rm test/dump/* || true

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
