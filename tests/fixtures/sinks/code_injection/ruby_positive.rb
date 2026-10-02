class ReportsController < ApplicationController
  def run # taint: route
    report = ReportRunner.new(current_account)
    render json: report.send(params[:report]) # taint: sink
  end
end
