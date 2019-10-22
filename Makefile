.SILENT:

docs:
	jsdoc README.md src/*.js index.js -d docs -c .jsdoc.config.js

deps:
	npm install

lint:
	npx standard

test: deps
	npx mocha

quicktest:
	npx mocha

watch: deps
	nodemon --watch index.js --watch README.md --watch src --watch test \
		--exec "rm -rf docs; make docs; make lint; make quicktest"

clean:
	rm -rf orbitdb
	rm -rf package-lock.json
	rm -rf node_modules

rebuild: clean deps
