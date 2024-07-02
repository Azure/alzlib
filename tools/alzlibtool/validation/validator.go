package validation

type Validator struct {
	funcs []ValidateFunc
}

type ValidateFunc func(any) error

func NewValidator(funcs ...ValidateFunc) Validator {
	return Validator{
		funcs: funcs,
	}
}

func (v *Validator) Validate(resource any) error {
	errs := newValidateError()
	for _, f := range v.funcs {
		if err := f(resource); err != nil {
			errs.add(err)
		}
	}
	if errs.HasErrors() {
		return errs
	}
	return nil
}
