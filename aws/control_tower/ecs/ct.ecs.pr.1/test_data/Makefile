all: pass.json fail.json
	@echo "Build outputs: pass.json fail.json"

.terraform:
	tofu init

pass.tfplan: .terraform main.tofu pass/main.tofu
	tofu plan --exclude module.fail --out=pass.tfplan

fail.tfplan: .terraform main.tofu fail/main.tofu
	tofu plan --exclude module.pass --out=fail.tfplan


%.json: %.tfplan
	tofu show -json $< > $@
