def run_report(expr):
    # Dangerous sink, but unreachable from a route that never calls this.
    return eval(expr)
