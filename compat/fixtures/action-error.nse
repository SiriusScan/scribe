-- Original Scribe fixture (MIT). A plain runtime error must stay a
-- failure class of its own: it is neither a pass nor "unsupported".
description = [[Original fixture: action raises an error]]
categories = {"safe"}

hostrule = function()
  return true
end

action = function()
  error("fixture blew up on purpose")
end
