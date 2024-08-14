/**
 * @name SQL injection
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.security.injection.Sql
import DataFlow::PathGraph

from SqlInjectionFlowConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on $@.", source.getNode(), "a user-provided value"