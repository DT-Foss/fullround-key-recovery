#include <cadical.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

struct DeadlineTerminator final : CaDiCaL::Terminator {
  explicit DeadlineTerminator(double seconds)
      : deadline(Clock::now() + std::chrono::duration_cast<Clock::duration>(
                                    std::chrono::duration<double>(seconds))) {}

  bool terminate() override {
    if (Clock::now() < deadline) return false;
    fired = true;
    return true;
  }

  Clock::time_point deadline;
  bool fired = false;
};

struct Arguments {
  std::string cnf;
  std::string mode;
  std::vector<int> assumption_one_literals;
  std::vector<int> model_one_literals;
  std::vector<std::string> cell_order;
  double seconds = 0.0;
  int max_cells = 256;
};

std::vector<std::string> split(const std::string &raw, char delimiter) {
  std::vector<std::string> result;
  std::stringstream stream(raw);
  std::string item;
  while (std::getline(stream, item, delimiter)) result.push_back(item);
  return result;
}

std::vector<int> parse_signed_literals(const std::string &raw,
                                       const char *label) {
  std::vector<int> result;
  for (const std::string &item : split(raw, ',')) {
    if (item.empty())
      throw std::runtime_error(std::string(label) + " has an empty item");
    std::size_t consumed = 0;
    const long value = std::stol(item, &consumed);
    if (consumed != item.size() || value == 0 || value < -INT32_MAX ||
        value > INT32_MAX)
      throw std::runtime_error(std::string(label) +
                               " contains an invalid signed literal");
    result.push_back(static_cast<int>(value));
  }
  return result;
}

double parse_positive_double(const std::string &raw, const char *label) {
  std::size_t consumed = 0;
  const double value = std::stod(raw, &consumed);
  if (consumed != raw.size() || value <= 0.0)
    throw std::runtime_error(std::string(label) + " must be positive");
  return value;
}

int parse_positive_int(const std::string &raw, const char *label) {
  std::size_t consumed = 0;
  const long value = std::stol(raw, &consumed);
  if (consumed != raw.size() || value <= 0 || value > 256)
    throw std::runtime_error(std::string(label) + " must be in 1 through 256");
  return static_cast<int>(value);
}

bool is_binary_width(const std::string &value, std::size_t width) {
  return value.size() == width &&
         std::all_of(value.begin(), value.end(),
                     [](char bit) { return bit == '0' || bit == '1'; });
}

Arguments parse_arguments(int argc, char **argv) {
  Arguments result;
  for (int index = 1; index < argc; index += 2) {
    if (index + 1 >= argc) throw std::runtime_error("option without value");
    const std::string option = argv[index];
    const std::string value = argv[index + 1];
    if (option == "--cnf")
      result.cnf = value;
    else if (option == "--mode")
      result.mode = value;
    else if (option == "--assumption-one-literals")
      result.assumption_one_literals =
          parse_signed_literals(value, "assumption-one-literals");
    else if (option == "--model-one-literals")
      result.model_one_literals =
          parse_signed_literals(value, "model-one-literals");
    else if (option == "--cell-order")
      result.cell_order = split(value, ',');
    else if (option == "--seconds")
      result.seconds = parse_positive_double(value, "seconds");
    else if (option == "--max-cells")
      result.max_cells = parse_positive_int(value, "max-cells");
    else
      throw std::runtime_error("unknown option: " + option);
  }
  if (result.cnf.empty() || result.mode.empty() || result.seconds <= 0.0)
    throw std::runtime_error("cnf, mode, and seconds are required");
  if (result.assumption_one_literals.size() != 8)
    throw std::runtime_error(
        "exactly eight assumption-one-literals are required");
  if (result.model_one_literals.size() != 20)
    throw std::runtime_error("exactly twenty model-one-literals are required");
  std::set<int> assumption_variables;
  for (const int literal : result.assumption_one_literals)
    assumption_variables.insert(std::abs(literal));
  std::set<int> model_variables;
  for (const int literal : result.model_one_literals)
    model_variables.insert(std::abs(literal));
  if (assumption_variables.size() != 8 || model_variables.size() != 20)
    throw std::runtime_error("mapped variables must be distinct within each role");
  if (result.cell_order.size() != 256)
    throw std::runtime_error("cell order must contain 256 entries");
  std::set<std::string> observed;
  for (const std::string &cell : result.cell_order) {
    if (!is_binary_width(cell, 8))
      throw std::runtime_error("cell order entries must be eight-bit binary");
    observed.insert(cell);
  }
  if (observed.size() != 256)
    throw std::runtime_error(
        "cell order must cover every eight-bit value exactly once");
  return result;
}

int64_t statistic(CaDiCaL::Solver &solver, const char *name) {
  const int64_t value = solver.get_statistic_value(name);
  if (value < 0)
    throw std::runtime_error(std::string("unsupported statistic: ") + name);
  return value;
}

std::string status_name(int status) {
  if (status == 0) return "unknown";
  if (status == 10) return "sat";
  if (status == 20) return "unsat";
  throw std::runtime_error("unexpected CaDiCaL status");
}

void print_integer_array(const std::vector<int> &values) {
  std::cout << '[';
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index) std::cout << ',';
    std::cout << values[index];
  }
  std::cout << ']';
}

void print_int64_array(const std::vector<int64_t> &values) {
  std::cout << '[';
  for (std::size_t index = 0; index < values.size(); ++index) {
    if (index) std::cout << ',';
    std::cout << values[index];
  }
  std::cout << ']';
}

bool literal_is_true_in_model(CaDiCaL::Solver &solver, int literal) {
  const int value = solver.val(std::abs(literal));
  if (value == 0)
    throw std::runtime_error("model variable has no Boolean value");
  return (value > 0) == (literal > 0);
}

}  // namespace

int main(int argc, char **argv) {
  try {
    const Arguments arguments = parse_arguments(argc, argv);
    CaDiCaL::Solver solver;
    if (!solver.set("quiet", 1) || !solver.set("reverse", 1))
      throw std::runtime_error("required CaDiCaL options are unavailable");
    int variables = 0;
    if (const char *error =
            solver.read_dimacs(arguments.cnf.c_str(), variables, 1))
      throw std::runtime_error(std::string("DIMACS read failed: ") + error);
    std::set<int> frozen;
    for (const int literal : arguments.assumption_one_literals)
      frozen.insert(std::abs(literal));
    for (const int literal : arguments.model_one_literals)
      frozen.insert(std::abs(literal));
    for (const int variable : frozen) {
      if (variable > variables)
        throw std::runtime_error("mapped variable exceeds CNF header");
      solver.freeze(variable);
    }

    const char *metric_names[] = {"conflicts", "decisions", "propagations"};
    int sat = 0, unsat = 0, unknown = 0, terminator_fires = 0;
    int attempted = 0;
    bool stopped_after_sat = false;
    for (int cell_index = 0; cell_index < arguments.max_cells; ++cell_index) {
      const std::string &prefix8 = arguments.cell_order[cell_index];
      std::vector<int> assumptions;
      for (std::size_t bit = 0; bit < 8; ++bit) {
        const int one_literal = arguments.assumption_one_literals[bit];
        assumptions.push_back(prefix8[bit] == '1' ? one_literal : -one_literal);
      }
      std::vector<int64_t> before;
      for (const char *metric : metric_names)
        before.push_back(statistic(solver, metric));
      const int active_before = solver.active();
      const int64_t irredundant_before = solver.irredundant();
      const int64_t redundant_before = solver.redundant();
      for (const int literal : assumptions) solver.assume(literal);

      DeadlineTerminator terminator(arguments.seconds);
      solver.connect_terminator(&terminator);
      const auto started = Clock::now();
      const int status = solver.solve();
      const double elapsed =
          std::chrono::duration<double>(Clock::now() - started).count();
      solver.disconnect_terminator();
      ++attempted;
      if (terminator.fired) ++terminator_fires;

      std::vector<int64_t> after;
      std::vector<int64_t> delta;
      for (std::size_t metric = 0; metric < 3; ++metric) {
        after.push_back(statistic(solver, metric_names[metric]));
        delta.push_back(after.back() - before[metric]);
      }
      const int active_after = solver.active();
      const int64_t irredundant_after = solver.irredundant();
      const int64_t redundant_after = solver.redundant();

      std::vector<int> model_bits;
      if (status == 10) {
        ++sat;
        for (const int literal : arguments.model_one_literals)
          model_bits.push_back(literal_is_true_in_model(solver, literal) ? 1
                                                                         : 0);
      } else if (status == 20) {
        ++unsat;
      } else {
        ++unknown;
      }
      std::vector<int> failed_assumptions;
      if (status == 20)
        for (const int literal : assumptions)
          if (solver.failed(literal)) failed_assumptions.push_back(literal);

      std::cout << "R20_RANKED_RESULT {\"mode\":\"" << arguments.mode
                << "\",\"prefix8\":\"" << prefix8
                << "\",\"cell_index\":" << cell_index << ",\"status\":\""
                << status_name(status) << "\",\"returncode\":" << status
                << ",\"seconds_budget\":" << std::setprecision(17)
                << arguments.seconds << ",\"elapsed_seconds\":" << elapsed
                << ",\"terminator_fired\":"
                << (terminator.fired ? "true" : "false")
                << ",\"assumptions\":";
      print_integer_array(assumptions);
      std::cout << ",\"failed_assumptions\":";
      print_integer_array(failed_assumptions);
      std::cout << ",\"model_bits_bit0_through_bit19\":";
      print_integer_array(model_bits);
      std::cout << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]";
      std::cout << ",\"metrics_before\":";
      print_int64_array(before);
      std::cout << ",\"metrics_after\":";
      print_int64_array(after);
      std::cout << ",\"metrics_delta\":";
      print_int64_array(delta);
      std::cout << ",\"active_variables_before\":" << active_before
                << ",\"active_variables_after\":" << active_after
                << ",\"active_variables_delta\":"
                << active_after - active_before
                << ",\"irredundant_clauses_before\":" << irredundant_before
                << ",\"irredundant_clauses_after\":" << irredundant_after
                << ",\"irredundant_clauses_delta\":"
                << irredundant_after - irredundant_before
                << ",\"redundant_clauses_before\":" << redundant_before
                << ",\"redundant_clauses_after\":" << redundant_after
                << ",\"redundant_clauses_delta\":"
                << redundant_after - redundant_before << "}\n";
      std::cout.flush();
      if (status == 10) {
        stopped_after_sat = true;
        break;
      }
    }
    std::cout << "R20_RANKED_SUMMARY {\"signature\":\""
              << CaDiCaL::Solver::signature() << "\",\"version\":\""
              << CaDiCaL::Solver::version() << "\",\"mode\":\""
              << arguments.mode << "\",\"variables\":" << variables
              << ",\"planned_max_cells\":" << arguments.max_cells
              << ",\"attempted_cells\":" << attempted << ",\"sat\":" << sat
              << ",\"unsat\":" << unsat << ",\"unknown\":" << unknown
              << ",\"terminator_fires\":" << terminator_fires
              << ",\"stopped_after_sat\":"
              << (stopped_after_sat ? "true" : "false")
              << ",\"seconds_budget\":" << arguments.seconds
              << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "R20_RANKED_ERROR " << error.what() << '\n';
    return 2;
  }
}
