#!/usr/bin/python

import sys

from lark import Lark
from lark import Transformer

class GrammarTransformer(Transformer):
	def prog0(self, param):
		principal = param[0].children[0]
		user = param[1].children[0]
		#print(param)
		#return param
		print(param)

	def cmd0(self, param):
		print(param)

	def cmd1(self, param):
		print(param)

	def cmd2(self, param):
		print(param)
	
	def expr0(self, param):
		print(param)

	def expr1(self, param):
		print(param)

	def expr2(self, param):
		print(param)

	def fieldvals0(self, param):
		print(param)

	def fieldvals1(self, param):
		print(param)

	def value0(self, param):
		print(param)

	def value1(self, param):
		print(param)

	def value2(self, param):
		print(param)

	def prim_cmd0(self, param):
		print(param)

	def prim_cmd1(self, param):
		print(param)

	def prim_cmd2(self, param):
		#print(param)
		#print('--------------------------------')
		print(param)

	def prim_cmd3(self, param):
		print(param)

	def prim_cmd4(self, param):
		print(param)

	def prim_cmd5(self, param):
		print(param)

	def prim_cmd6(self, param):
		print(param)

	def prim_cmd7(self, param):
		print(param)

	def prim_cmd8(self, param):
		print(param)

	def tgt0(self, param):
		print(param)

	def tgt1(self, param):
		print(param)

	def right0(self, param):
		print(param)

	def right1(self, param):
		print(param)

	def right2(self, param):
		print(param)

	def right3(self, param):
		print(param)


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


def messageHandler(text):
	tree = grammar.parse(text)
	GrammarTransformer.transform(tree)



#--------------------------------------------------------------------------------



print(grammar.parse('as principal bob password "B0BPWxxd" do \n set z = "bobs string" \n set x = "another string" \n return x \n ***').pretty())

print('\n\n\n\n')

tree = grammar.parse('as principal bob password "B0BPWxxd" do \n set z = "bobs string" \n set x = "another string" \n return x \n ***')
print(GrammarTransformer().transform(tree))

#tree = grammar.parse('as principal bob password "B0BPWxxd" do \n set x = "test string" \n set delegation x mike read -> bob \n return x \n ***')
#GrammarTransformer().transform(tree)

