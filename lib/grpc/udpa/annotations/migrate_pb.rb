# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: udpa/annotations/migrate.proto

require 'google/protobuf'

Google::Protobuf::DescriptorPool.generated_pool.build do
  add_file("udpa/annotations/migrate.proto", :syntax => :proto3) do
    add_message "udpa.annotations.MigrateAnnotation" do
      optional :rename, :string, 1
    end
    add_message "udpa.annotations.FieldMigrateAnnotation" do
      optional :rename, :string, 1
      optional :oneof_promotion, :string, 2
    end
    add_message "udpa.annotations.FileMigrateAnnotation" do
      optional :move_to_package, :string, 2
    end
  end
end

module Udpa
  module Annotations
    MigrateAnnotation = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("udpa.annotations.MigrateAnnotation").msgclass
    FieldMigrateAnnotation = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("udpa.annotations.FieldMigrateAnnotation").msgclass
    FileMigrateAnnotation = ::Google::Protobuf::DescriptorPool.generated_pool.lookup("udpa.annotations.FileMigrateAnnotation").msgclass
  end
end
