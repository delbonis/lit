import testlib
import test_combinators

def run_test_forward(env):
    lit1 = env.lits[0]
    lit2 = env.lits[1]
    test_combinators.run_close_test(env, lit1, lit2, lit1)

def run_test_reverse(env):
    lit1 = env.lits[0]
    lit2 = env.lits[1]
    test_combinators.run_close_test(env, lit1, lit2, lit1)
