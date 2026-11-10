package base

import (
	rt "github.com/SiriusScan/scribe/internal/thirdparty/golua/runtime"
)

func getmetatable(t *rt.Thread, c *rt.GoCont) (rt.Cont, error) {
	if err := c.Check1Arg(); err != nil {
		return nil, err
	}
	return c.PushingNext(t.Runtime, t.Metatable(c.Arg(0))), nil
}
