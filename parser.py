#!/usr/bin/python

import sys

from lark import Lark

grammar = Lark(r"""
	prog		: "as" "principal" p "password" s "do" "\n" cmd
	cmd 		: "exit" "\n" 
				| "return" expr "\n"
				| prim_cmd "\n" cmd
	expr		: value 
				| "[]" 
				| "{" fieldvals "}"
	fieldvals	: x "=" value
				| x "=" value "," fieldvals
	value		: x
				| x "." y
				| s 
	prim_cmd	: "create" "principal" p s
				| "change" "password" p s
				| "set" x "=" expr
				| "append" "to" x "with" expr
				| "local" x "=" expr
				| "foreach" y "in" x "replacewith" expr
				| "set" "delegation" tgt q right "->" p
				| "delete" "delegation" tgt q right "->" p
				| "default" "delegator" "=" p
	tgt 		: "all"
				| x
	right 		: "read"
				| "write"
				| "append"
				| "delegate"
	p			: WORD
	q			: WORD
	s 			: ESCAPED_STRING
	x			: WORD
	y			: WORD

	%import common.WORD
	%import common.ESCAPED_STRING
	%import common.WS
	%ignore /[ \t\f\r]+/
	
	""", start='prog')

print(grammar.parse('as principal bob password "B0BPWxxd" do \n set z = "bobs string" \n set x = "another string" \n return x \n').pretty())
