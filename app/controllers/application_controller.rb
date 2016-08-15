class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_tenant!
  
     ##    milia defines a default max_tenants, invalid_tenant exception handling
     ##    but you can override these if you wish to handle directly
  rescue_from ::Milia::Control::MaxTenantExceeded, :with => :max_tenants
  rescue_from ::Milia::Control::InvalidTenantAccess, :with => :invalid_tenant


  def authenticate_tenant!()
    unless current_user.present? || authenticate_user!(force: true)
      email = ( params.nil? || params[:user].nil?  ?  "<email missing>"  : params[:user][:email] )
      flash[:error] = "cannot sign in as #{email}; check email/password"
      logger.info("MILIA >>>>> [failed auth user] ") unless logger.nil?
      return false  # abort the before_filter chain
    end

    trace_tenanting( "authenticate_tenant!" )

    # user_signed_in? == true also means current_user returns valid user
    raise SecurityError,"*** invalid user_signed_in  ***" unless user_signed_in?

    set_current_tenant   # relies on current_user being non-nil

      # successful tenant authentication; do any callback
    if self.respond_to?( :callback_authenticate_tenant, true )
      logger.debug("MILIA >>>>> [auth_tenant callback]")
      self.send( :callback_authenticate_tenant )
    end

    true  # allows before filter chain to continue
  end
  
end
