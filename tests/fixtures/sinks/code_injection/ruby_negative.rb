class ReportsController < ApplicationController
  def run # taint: route
    report = ReportRunner.new(current_account)
    render json: report.send(:daily_summary) # taint: sink
  end
end
