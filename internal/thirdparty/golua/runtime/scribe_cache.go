// SPDX-License-Identifier: Apache-2.0

package runtime

// BindCode binds an immutable compiled code template to a fresh environment.
// The caller accounts for retained code memory before binding. Code and its
// constants must never contain closures, tables or mutable invocation values.
func (r *Runtime) BindCode(c *Code, env Value) *Closure {
	closure := NewClosure(r, c)
	if c.UpvalueCount > 0 {
		closure.AddUpvalue(newCell(env))
	}
	return closure
}
