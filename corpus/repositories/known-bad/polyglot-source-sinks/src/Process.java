final class Process {
  void run(Request request) throws Exception {
    Runtime.getRuntime().exec(request.getParameter("cmd"));
  }
}
