import python
import semmle.python.security.injection.Sql

class SQLInjectionVulnerability extends SqlInjection::Configuration {
  SQLInjectionVulnerability() { this = "SQLInjectionVulnerability" }

  override predicate isSource(DataFlow::Node source) {
    exists(FunctionValue func |
      func.getName() = "authenticate" and
      source.asExpr() = func.getArgument(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CallNode call |
      call.getFunction().toString() = "cursor.execute" and
      sink.asExpr() = call.getArg(0)
    )
  }
}

from SQLInjectionVulnerability config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Potential SQL injection vulnerability due to $@.", source, "user-provided value"