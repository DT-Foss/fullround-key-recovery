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
  double global_seconds = 0.0;
  double discovery_seconds = 0.0;
  double fallback_seconds = 0.0;
};

struct Outcome {
  int status = 0;
  bool terminator_fired = false;
  std::string prefix8;
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
    else if (option == "--global-seconds")
      result.global_seconds = parse_positive_double(value, "global-seconds");
    else if (option == "--discovery-seconds")
      result.discovery_seconds =
          parse_positive_double(value, "discovery-seconds");
    else if (option == "--fallback-seconds")
      result.fallback_seconds =
          parse_positive_double(value, "fallback-seconds");
    else
      throw std::runtime_error("unknown option: " + option);
  }
  if (result.cnf.empty() || result.mode.empty() ||
      result.global_seconds <= 0.0 || result.discovery_seconds <= 0.0 ||
      result.fallback_seconds <= 0.0)
    throw std::runtime_error("cnf, mode, and all three budgets are required");
  if (result.assumption_one_literals.size() != 8)
    throw std::runtime_error(
        "exactly eight assumption-one-literals are required");
  if (result.model_one_literals.size() != 20)
    throw std::runtime_error("exactly twenty model-one-literals are required");
  if (result.cell_order.size() != 128)
    throw std::runtime_error("cell order must contain exactly 128 entries");
  std::set<int> assumption_variables;
  for (const int literal : result.assumption_one_literals)
    assumption_variables.insert(std::abs(literal));
  std::set<int> model_variables;
  for (const int literal : result.model_one_literals)
    model_variables.insert(std::abs(literal));
  if (assumption_variables.size() != 8 || model_variables.size() != 20)
    throw std::runtime_error("mapped variables must be distinct within each role");
  std::set<std::string> observed;
  for (const std::string &cell : result.cell_order) {
    if (!is_binary_width(cell, 8))
      throw std::runtime_error("cell order entries must be eight-bit binary");
    observed.insert(cell);
  }
  if (observed.size() != 128)
    throw std::runtime_error("cell order must contain 128 unique prefixes");
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

std::vector<int> assumptions_for(
    const std::string &prefix8,
    const std::vector<int> &assumption_one_literals) {
  std::vector<int> assumptions;
  for (std::size_t bit = 0; bit < 8; ++bit) {
    const int one_literal = assumption_one_literals[bit];
    assumptions.push_back(prefix8[bit] == '1' ? one_literal : -one_literal);
  }
  return assumptions;
}

Outcome solve_once(CaDiCaL::Solver &solver, const Arguments &arguments,
                   const std::string &phase, int attempt_index,
                   int cell_index, const std::string &prefix8,
                   double seconds) {
  const std::vector<int> assumptions =
      prefix8.empty()
          ? std::vector<int>{}
          : assumptions_for(prefix8, arguments.assumption_one_literals);
  const char *metric_names[] = {"conflicts", "decisions", "propagations"};
  std::vector<int64_t> before;
  for (const char *metric : metric_names)
    before.push_back(statistic(solver, metric));
  const int active_before = solver.active();
  const int64_t irredundant_before = solver.irredundant();
  const int64_t redundant_before = solver.redundant();
  for (const int literal : assumptions) solver.assume(literal);

  DeadlineTerminator terminator(seconds);
  solver.connect_terminator(&terminator);
  const auto started = Clock::now();
  const int status = solver.solve();
  const double elapsed =
      std::chrono::duration<double>(Clock::now() - started).count();
  solver.disconnect_terminator();

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
  if (status == 10)
    for (const int literal : arguments.model_one_literals)
      model_bits.push_back(literal_is_true_in_model(solver, literal) ? 1 : 0);
  std::vector<int> failed_assumptions;
  if (status == 20)
    for (const int literal : assumptions)
      if (solver.failed(literal)) failed_assumptions.push_back(literal);

  std::cout << "R20_RESIDUAL_RESULT {\"mode\":\"" << arguments.mode
            << "\",\"phase\":\"" << phase << "\",\"attempt_index\":"
            << attempt_index << ",\"cell_index\":" << cell_index
            << ",\"prefix8\":";
  if (prefix8.empty())
    std::cout << "null";
  else
    std::cout << '\"' << prefix8 << '\"';
  std::cout << ",\"status\":\"" << status_name(status)
            << "\",\"returncode\":" << status
            << ",\"seconds_budget\":" << std::setprecision(17) << seconds
            << ",\"elapsed_seconds\":" << elapsed
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
            << ",\"active_variables_delta\":" << active_after - active_before
            << ",\"irredundant_clauses_before\":" << irredundant_before
            << ",\"irredundant_clauses_after\":" << irredundant_after
            << ",\"irredundant_clauses_delta\":"
            << irredundant_after - irredundant_before
            << ",\"redundant_clauses_before\":" << redundant_before
            << ",\"redundant_clauses_after\":" << redundant_after
            << ",\"redundant_clauses_delta\":"
            << redundant_after - redundant_before << "}\n";
  std::cout.flush();
  return {status, terminator.fired, prefix8};
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

    int attempt_index = 0;
    int global_sat = 0, global_unsat = 0, global_unknown = 0;
    int discovery_sat = 0, discovery_unsat = 0, discovery_unknown = 0;
    int fallback_sat = 0, fallback_unsat = 0, fallback_unknown = 0;
    int terminator_fires = 0;
    bool stopped_after_sat = false;
    std::set<std::string> exact_unsat_prefixes;
    std::vector<std::string> fallback_cells;

    const Outcome global =
        solve_once(solver, arguments, "global", attempt_index++, -1, "",
                   arguments.global_seconds);
    terminator_fires += global.terminator_fired ? 1 : 0;
    if (global.status == 10) {
      ++global_sat;
      stopped_after_sat = true;
    } else if (global.status == 20) {
      ++global_unsat;
    } else {
      ++global_unknown;
    }

    if (global.status == 0) {
      for (std::size_t index = 0; index < arguments.cell_order.size(); ++index) {
        const std::string &prefix = arguments.cell_order[index];
        const Outcome row = solve_once(
            solver, arguments, "discovery", attempt_index++,
            static_cast<int>(index), prefix, arguments.discovery_seconds);
        terminator_fires += row.terminator_fired ? 1 : 0;
        if (row.status == 10) {
          ++discovery_sat;
          stopped_after_sat = true;
          break;
        }
        if (row.status == 20) {
          ++discovery_unsat;
          exact_unsat_prefixes.insert(prefix);
        } else {
          ++discovery_unknown;
          fallback_cells.push_back(prefix);
        }
      }
    }

    if (!stopped_after_sat && global.status == 0) {
      for (const std::string &prefix : fallback_cells) {
        const auto found = std::find(arguments.cell_order.begin(),
                                     arguments.cell_order.end(), prefix);
        if (found == arguments.cell_order.end())
          throw std::runtime_error("fallback prefix is outside frozen order");
        const int cell_index =
            static_cast<int>(found - arguments.cell_order.begin());
        const Outcome row =
            solve_once(solver, arguments, "fallback", attempt_index++,
                       cell_index, prefix, arguments.fallback_seconds);
        terminator_fires += row.terminator_fired ? 1 : 0;
        if (row.status == 10) {
          ++fallback_sat;
          stopped_after_sat = true;
          break;
        }
        if (row.status == 20) {
          ++fallback_unsat;
          exact_unsat_prefixes.insert(prefix);
        } else {
          ++fallback_unknown;
        }
      }
    }

    std::cout << "R20_RESIDUAL_SUMMARY {\"signature\":\""
              << CaDiCaL::Solver::signature() << "\",\"version\":\""
              << CaDiCaL::Solver::version() << "\",\"mode\":\""
              << arguments.mode << "\",\"variables\":" << variables
              << ",\"attempted_solves\":" << attempt_index
              << ",\"global_sat\":" << global_sat
              << ",\"global_unsat\":" << global_unsat
              << ",\"global_unknown\":" << global_unknown
              << ",\"discovery_sat\":" << discovery_sat
              << ",\"discovery_unsat\":" << discovery_unsat
              << ",\"discovery_unknown\":" << discovery_unknown
              << ",\"fallback_sat\":" << fallback_sat
              << ",\"fallback_unsat\":" << fallback_unsat
              << ",\"fallback_unknown\":" << fallback_unknown
              << ",\"exact_unsat_prefixes\":"
              << exact_unsat_prefixes.size()
              << ",\"terminator_fires\":" << terminator_fires
              << ",\"stopped_after_sat\":"
              << (stopped_after_sat ? "true" : "false")
              << ",\"global_seconds\":" << arguments.global_seconds
              << ",\"discovery_seconds\":" << arguments.discovery_seconds
              << ",\"fallback_seconds\":" << arguments.fallback_seconds
              << ",\"metric_names\":[\"conflicts\",\"decisions\",\"search_propagations\"]}\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "R20_RESIDUAL_ERROR " << error.what() << '\n';
    return 2;
  }
}
