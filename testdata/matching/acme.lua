-- Original MIT fixture; no upstream corpus compatibility claim.
-- scribe: {"match":{"products":["Acme"],"services":["http"],"min_version":"1.2.0","max_version":"2.0.0"}}
return {api_version=1,action=function() return {verdict="not_vulnerable"} end}
