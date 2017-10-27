#!/usr/bin/python

import sys

from lark import Lark

from lark import Transformer

class MyTransformer(Transformer):
	def prog0(self, items):
		print(items[0].children)
		

grammar = Lark(r"""
	prog		: "as" "principal" p "password" s "do" "\n" cmd "***"	-> prog0
	cmd 		: "exit" "\n" 											-> cmd0
				| "return" expr "\n"									-> cmd1
				| prim_cmd "\n" cmd 									-> cmd2
	expr		: value													-> expr0
				| "[]" 													-> expr1
				| "{" fieldvals "}"										-> expr2
	fieldvals	: x "=" value											-> fieldvals0
				| x "=" value "," fieldvals 							-> fieldvals1
	value		: x														-> value0
				| x "." y												-> value1
				| s 													-> value2
	prim_cmd	: "create" "principal" p s 								-> prim_cmd0
				| "change" "password" p s 								-> prim_cmd1
				| "set" x "=" expr 										-> prim_cmd2
				| "append" "to" x "with" expr 							-> prim_cmd3
				| "local" x "=" expr 									-> prim_cmd4
				| "foreach" y "in" x "replacewith" expr 				-> prim_cmd5
				| "set" "delegation" tgt q right "->" p 				-> prim_cmd6
				| "delete" "delegation" tgt q right "->" p 				-> prim_cmd7
				| "default" "delegator" "=" p 							-> prim_cmd8
	tgt 		: "all"													-> tgt0
				| x 													-> tgt1
	right 		: "read" 												-> right0
				| "write" 												-> right1
				| "append" 												-> right2
				| "delegate" 											-> right3
	p			: CNAME
	q			: CNAME
	s 			: ESCAPED_STRING
	x			: CNAME
	y			: CNAME

	%import common.WORD
	%import common.CNAME
	%import common.ESCAPED_STRING
	%import common.WS
	%ignore /[ \t\f\r]+/
	
	""", start='prog')



# print(grammar.parse('as principal admin password "B0BPWxxd" do \n set z = "bobs string" \n set x = "another string" \n return x \n').pretty())

# print(grammar.parse('as principal admin password "admin" do \n create principal bob "B0BPWxxd" \n set y ={f1=x,f2="field2"} \n set     delegation x admin read-> bob \n return y . f1 \n ***').pretty())

tree = grammar.parse('as principal admin password "admin" do \n create principal bob "B0BPWxxd" \n set y ={f1=x,f2="field2"} \n set     delegation x admin read-> bob \n return y . f1 \n ***')
MyTransformer().transform(tree)


# print(grammar.parse('as principal admin password "admin" do \n set records = [] \n append to records with { name = "mike", date = "1-1-90" } \n append to records with { name = "dave", date = "1-1-85" } \n local names = records \n foreach rec in names replacewith rec.name \n return names \n ***').pretty())



