package to

// ValOrZero returns the value of the pointer or the zero value of the type if the pointer is nil.
func ValOrZero[T any](v *T) T {
	if v == nil {
		var zero T
		return zero
	}
	return *v
}
