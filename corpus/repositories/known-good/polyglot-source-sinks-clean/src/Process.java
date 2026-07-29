final class Process {
  void run() throws Exception {
    Runtime.getRuntime().exec("/usr/bin/id");
  }
}
