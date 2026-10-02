class DiagController < ApplicationController
  def ping # taint: route
    host = params[:host]
    ok = system("ping", "-c", "1", host) # taint: sink
    head(ok ? :no_content : :bad_gateway)
  end
end
