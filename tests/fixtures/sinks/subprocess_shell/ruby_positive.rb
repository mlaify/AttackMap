class DiagController < ApplicationController
  def ping # taint: route
    host = params[:host]
    output = `ping -c 1 #{host}` # taint: sink
    render plain: output
  end
end
