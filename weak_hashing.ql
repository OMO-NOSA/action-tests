import python
import semmle.python.security.Crypto

class WeakHashingVulnerability extends Crypto::WeakHashing::Configuration {
  WeakHashingVulnerability() { this = "WeakHashingVulnerability" }

  override predicate isSource(DataFlow::Node source) {
    exists(CallNode call |
      call.getFunction().(AttrNode).getObject().toString() = "hashlib" and
      call.getFunction().(AttrNode).getAttributeName() = "md5" and
      source.asExpr() = call
    )
  }
}

from WeakHashingVulnerability config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink, "Use of weak hashing algorithm (MD5) $@.", source, "here"