deps:
	npm install

watch:
	nodemon --exec "npx mocha"

test: deps
	npx mocha
